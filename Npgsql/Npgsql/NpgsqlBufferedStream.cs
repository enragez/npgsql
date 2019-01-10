namespace Npgsql
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Resources;
    using System.Text;
    using System.Threading;

    /// <summary>Адаптер bufferedStream с блокировкой при конкурентных попытках чтения/записи в coкет, обернутый в bufferedStream </summary>
    public sealed class NpgsqlBufferedStream:IDisposable
    {
        private BufferedStream _stream;

        private ReaderWriterLockSlim _sync;
        
        public NpgsqlBufferedStream(BufferedStream stream)
        {
            _stream = stream;
            _sync = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
        }

        /// <summary>Заблокировать поток на запись</summary>
        public void EnterWriteLock()
        {
            if (!_sync.IsWriteLockHeld)
            {
                _sync.EnterWriteLock();
            }
        }

        /// <summary>Записать байты в поток</summary>
        /// <param name="buffer">байты для записи</param>
        /// <param name="offset">индекс первого байта</param>
        /// <param name="count">число байт для записи</param>
        public void Write(byte[] buffer, int offset, int count)
        {
            _stream.Write(buffer, offset, count);
        }
        
        /// <summary>Записать байт в поток</summary>
        /// <param name="byte">байт для записи</param>
        public void WriteByte(byte @byte)
        {
            _stream.WriteByte(@byte);
        }

        /// <summary>Атомарная операция чтения одного байта из потока</summary>
        public int ReadByte()
        {
            try
            {
                _sync.EnterReadLock();
                return _stream.ReadByte();
            }
            finally
            {
                _sync.ExitReadLock();
            }
        }
        
        /// <summary>Атомарная операция чтения байтов из потока</summary>
        /// <param name="buffer">массив байтов, к торорый производится чтение</param>
        /// <param name="offset">индекс в массиве, начиная с которого будут сохранены прочиатнные байты</param>
        /// <param name="count">количество читаемых байтов</param>
        /// <returns>количество прочитанных байтов</returns>
        public int Read(byte[] buffer, int offset, int count)
        {
            try
            {
                _sync.EnterReadLock();
                return _stream.Read(buffer, offset, count);
            }
            finally
            {
                _sync.ExitReadLock();
            }
        }

        /// <summary>Атомарная операция чтения строки из потока</summary>
        /// <returns>Прочитанная строка</returns>
        /// <exception cref="IOException">Исключение операции ввода/вывода из сокета</exception>
        public string ReadString()
        {
            try
            {
                _sync.EnterReadLock();
                var buffer = new List<byte>();
                for (int bRead = _stream.ReadByte(); bRead != 0; bRead = _stream.ReadByte())
                {
                    if (bRead == -1)
                    {
                        throw new IOException();
                    }
                    else
                    {
                        buffer.Add((byte) bRead);
                    }
                }

                return BackendEncoding.UTF8Encoding.GetString(buffer.ToArray());
            }
            finally
            {
                _sync.ExitReadLock();
            }
        }

        /// <summary>Атомарная операция чтения ответа от СУБД PostgreSQL</summary>
        /// <param name="context">Экземпляр <see cref="NpgsqlConnector"/></param>
        /// <param name="resman">Ресурсы</param>
        /// <returns>Коллекция сообщений, полученных от СУБД</returns>
        /// <exception cref="NpgsqlException"></exception>
        /// <exception cref="Exception"></exception>
        /// <exception cref="IOException"></exception>
        /// <exception cref="NotSupportedException"></exception>
        public IEnumerable<IServerResponseObject> ProcessBackendResponse(NpgsqlConnector context, ResourceManager resman)
        {
            try
            {
                _sync.EnterReadLock();
                NpgsqlMediator mediator = context.Mediator;

                List<NpgsqlError> errors = new List<NpgsqlError>();

                for (;;)
                {
                    // Check the first Byte of response.
                    BackEndMessageCode message = (BackEndMessageCode) _stream.ReadByte();
                    switch (message)
                    {
                        case BackEndMessageCode.ErrorResponse:

                            NpgsqlError error = new NpgsqlError(this);
                            error.ErrorSql = mediator.GetSqlSent();

                            errors.Add(error);

                            NpgsqlEventLog.LogMsg(resman, "Log_ErrorResponse", LogLevel.Debug, error.Message);

                            // Return imediately if it is in the startup state or connected state as
                            // there is no more messages to consume.
                            // Possible error in the NpgsqlStartupState:
                            //        Invalid password.
                            // Possible error in the NpgsqlConnectedState:
                            //        No pg_hba.conf configured.

                            if (!context.RequireReadyForQuery)
                            {
                                throw new NpgsqlException(errors);
                            }

                            break;
                        case BackEndMessageCode.AuthenticationRequest:

                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug,
                                "AuthenticationRequest");

                            // Get the length in case we're getting AuthenticationGSSContinue
                            int authDataLength = PGUtil.ReadInt32(_stream) - 8;

                            AuthenticationRequestType authType = (AuthenticationRequestType) PGUtil.ReadInt32(_stream);
                            switch (authType)
                            {
                                case AuthenticationRequestType.AuthenticationOk:
                                    NpgsqlEventLog.LogMsg(resman, "Log_AuthenticationOK", LogLevel.Debug);
                                    break;
                                case AuthenticationRequestType.AuthenticationClearTextPassword:
                                    NpgsqlEventLog.LogMsg(resman, "Log_AuthenticationClearTextRequest", LogLevel.Debug);

                                    // Send the PasswordPacket.

                                    context.CurrentState = NpgsqlStartupState.Instance;
                                    
                                    _sync.ExitReadLock();
                                    context.Authenticate(NullTerminateArray(context.Password));

                                    break;
                                case AuthenticationRequestType.AuthenticationMD5Password:
                                    NpgsqlEventLog.LogMsg(resman, "Log_AuthenticationMD5Request", LogLevel.Debug);
                                    // Now do the "MD5-Thing"
                                    // for this the Password has to be:
                                    // 1. md5-hashed with the username as salt
                                    // 2. md5-hashed again with the salt we get from the backend

                                    MD5 md5 = MD5.Create();

                                    // 1.
                                    byte[] passwd = context.Password;
                                    byte[] saltUserName = BackendEncoding.UTF8Encoding.GetBytes(context.UserName);

                                    byte[] crypt_buf = new byte[passwd.Length + saltUserName.Length];

                                    passwd.CopyTo(crypt_buf, 0);
                                    saltUserName.CopyTo(crypt_buf, passwd.Length);

                                    StringBuilder sb = new StringBuilder();
                                    byte[] hashResult = md5.ComputeHash(crypt_buf);
                                    foreach (byte b in hashResult)
                                    {
                                        sb.Append(b.ToString("x2"));
                                    }

                                    String prehash = sb.ToString();

                                    byte[] prehashbytes = BackendEncoding.UTF8Encoding.GetBytes(prehash);
                                    crypt_buf = new byte[prehashbytes.Length + 4];

                                    _stream.Read(crypt_buf, prehashbytes.Length, 4);
                                    // Send the PasswordPacket.
                                    context.CurrentState = NpgsqlStartupState.Instance;

                                    // 2.
                                    prehashbytes.CopyTo(crypt_buf, 0);

                                    sb = new StringBuilder(
                                        "md5"); // This is needed as the backend expects md5 result starts with "md5"
                                    hashResult = md5.ComputeHash(crypt_buf);
                                    foreach (byte b in hashResult)
                                    {
                                        sb.Append(b.ToString("x2"));
                                    }

                                    _sync.ExitReadLock();
                                    context.Authenticate(
                                        NullTerminateArray(BackendEncoding.UTF8Encoding.GetBytes(sb.ToString())));

                                    break;
#if WINDOWS && UNMANAGED

                                case AuthenticationRequestType.AuthenticationGSS:
                                {
                                    if (context.IntegratedSecurity)
                                    {
                                        // For GSSAPI we have to use the supplied hostname
                                        context.SSPI = new SSPIHandler(context.Host, context.Krbsrvname, true);
                                        context.CurrentState = NpgsqlStartupState.Instance;
                                        
                                        _sync.ExitReadLock();
                                        context.Authenticate(context.SSPI.Continue(null));
                                        break;
                                    }
                                    else
                                    {
                                        // TODO: correct exception
                                        throw new Exception();
                                    }
                                }

                                case AuthenticationRequestType.AuthenticationSSPI:
                                {
                                    if (context.IntegratedSecurity)
                                    {
                                        context.SSPI = new SSPIHandler(context.Host, context.Krbsrvname, false);
                                        context.CurrentState = NpgsqlStartupState.Instance;
                                        
                                        _sync.ExitReadLock();
                                        context.Authenticate(context.SSPI.Continue(null));
                                        break;
                                    }
                                    else
                                    {
                                        // TODO: correct exception
                                        throw new Exception();
                                    }
                                }

                                case AuthenticationRequestType.AuthenticationGSSContinue:
                                {
                                    byte[] authData = new byte[authDataLength];
                                    PGUtil.CheckedStreamRead(_stream, authData, 0, authDataLength);
                                    byte[] passwd_read = context.SSPI.Continue(authData);
                                    if (passwd_read.Length != 0)
                                    {
                                        _sync.ExitReadLock();
                                        context.Authenticate(passwd_read);
                                    }

                                    break;
                                }

#endif

                                default:
                                    // Only AuthenticationClearTextPassword and AuthenticationMD5Password supported for now.
                                    errors.Add(new NpgsqlError(String.Format(
                                        resman.GetString("Exception_AuthenticationMethodNotSupported"), authType)));

                                    throw new NpgsqlException(errors);
                            }

                            break;
                        case BackEndMessageCode.RowDescription:
                            yield return new NpgsqlRowDescription(_stream, context.OidToNameMapping,
                                context.CompatVersion);
                            break;

                        case BackEndMessageCode.ParameterDescription:

                            // Do nothing,for instance,  just read...
                            int lenght = PGUtil.ReadInt32(_stream);
                            int nb_param = PGUtil.ReadInt16(_stream);
                            for (int i = 0; i < nb_param; i++)
                            {
                                int typeoid = PGUtil.ReadInt32(_stream);
                            }

                            break;

                        case BackEndMessageCode.DataRow:
                            yield return new StringRowReader(_stream);
                            break;

                        case BackEndMessageCode.ReadyForQuery:

//                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug, "ReadyForQuery");

                            // Possible status bytes returned:
                            //   I = Idle (no transaction active).
                            //   T = In transaction, ready for more.
                            //   E = Error in transaction, queries will fail until transaction aborted.
                            // Just eat the status byte, we have no use for it at this time.
                            PGUtil.ReadInt32(_stream);
                            _stream.ReadByte();

                            context.CurrentState = NpgsqlReadyState.Instance;

                            if (errors.Count != 0)
                            {
                                throw new NpgsqlException(errors);
                            }

                            yield break;

                        case BackEndMessageCode.BackendKeyData:

                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug, "BackendKeyData");
                            // BackendKeyData message.
                            NpgsqlBackEndKeyData backend_keydata = new NpgsqlBackEndKeyData(_stream);
                            context.BackEndKeyData = backend_keydata;

                            // Wait for ReadForQuery message
                            break;

                        case BackEndMessageCode.NoticeResponse:
                            // Notices and errors are identical except that we
                            // just throw notices away completely ignored.
                            context.FireNotice(new NpgsqlError(this));
                            break;

                        case BackEndMessageCode.CompletedResponse:
                            PGUtil.ReadInt32(_stream);
                            yield return new CompletedResponse(_stream);
                            break;
                        case BackEndMessageCode.ParseComplete:
                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug, "ParseComplete");
                            // Just read up the message length.
                            PGUtil.ReadInt32(_stream);
                            break;
                        case BackEndMessageCode.BindComplete:
//                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug, "BindComplete");
                            // Just read up the message length.
                            PGUtil.ReadInt32(_stream);
                            break;
                        case BackEndMessageCode.EmptyQueryResponse:
                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug, "EmptyQueryResponse");
                            PGUtil.ReadInt32(_stream);
                            break;
                        case BackEndMessageCode.NotificationResponse:
                            // Eat the length
                            PGUtil.ReadInt32(_stream);
                            context.FireNotification(new NpgsqlNotificationEventArgs(_stream, true));
                            if (context.IsNotificationThreadRunning)
                            {
                                yield break;
                            }

                            break;
                        case BackEndMessageCode.ParameterStatus:
                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug, "ParameterStatus");
                            NpgsqlParameterStatus parameterStatus = new NpgsqlParameterStatus(_stream);

                            NpgsqlEventLog.LogMsg(resman, "Log_ParameterStatus", LogLevel.Debug,
                                parameterStatus.Parameter,
                                parameterStatus.ParameterValue);

                            context.AddParameterStatus(parameterStatus);

                            if (parameterStatus.Parameter == "server_version")
                            {
                                // Deal with this here so that if there are
                                // changes in a future backend version, we can handle it here in the
                                // protocol handler and leave everybody else put of it.
                                string versionString = parameterStatus.ParameterValue.Trim();
                                for (int idx = 0; idx != versionString.Length; ++idx)
                                {
                                    char c = parameterStatus.ParameterValue[idx];
                                    if (!char.IsDigit(c) && c != '.')
                                    {
                                        versionString = versionString.Substring(0, idx);
                                        break;
                                    }
                                }

                                context.ServerVersion = new Version(versionString);
                            }

                            break;
                        case BackEndMessageCode.NoData:
                            // This nodata message may be generated by prepare commands issued with queries which doesn't return rows
                            // for example insert, update or delete.
                            // Just eat the message.
                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug, "ParameterStatus");
                            PGUtil.ReadInt32(_stream);
                            break;

                        case BackEndMessageCode.CopyInResponse:
                            // Enter COPY sub protocol and start pushing data to server
                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug, "CopyInResponse");
                            context.CurrentState = new NpgsqlCopyInState();
                            PGUtil.ReadInt32(_stream); // length redundant
                            context.CurrentState.StartCopy(context, ReadCopyHeader(_stream));
                            yield break;
                        // Either StartCopy called us again to finish the operation or control should be passed for user to feed copy data

                        case BackEndMessageCode.CopyOutResponse:
                            // Enter COPY sub protocol and start pulling data from server
                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug, "CopyOutResponse");
                            context.CurrentState = NpgsqlCopyOutState.Instance;
                            PGUtil.ReadInt32(_stream); // length redundant
                            context.CurrentState.StartCopy(context, ReadCopyHeader(_stream));
                            yield break;
                        // Either StartCopy called us again to finish the operation or control should be passed for user to feed copy data

                        case BackEndMessageCode.CopyData:
                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug, "CopyData");
                            Int32 len = PGUtil.ReadInt32(_stream) - 4;
                            byte[] buf = new byte[len];
                            PGUtil.ReadBytes(_stream, buf, 0, len);
                            context.Mediator.ReceivedCopyData = buf;
                            yield
                                break; // read data from server one chunk at a time while staying in copy operation mode

                        case BackEndMessageCode.CopyDone:
                            NpgsqlEventLog.LogMsg(resman, "Log_ProtocolMessage", LogLevel.Debug, "CopyDone");
                            PGUtil.ReadInt32(_stream); // CopyDone can not have content so this is always 4
                            // This will be followed by normal CommandComplete + ReadyForQuery so no op needed
                            break;

                        case BackEndMessageCode.IO_ERROR:
                            // Connection broken. Mono returns -1 instead of throwing an exception as ms.net does.
                            throw new IOException();

                        default:
                            // This could mean a number of things
                            //   We've gotten out of sync with the backend?
                            //   We need to implement this type?
                            //   Backend has gone insane?
                            // FIXME
                            // what exception should we really throw here?
                            throw new NotSupportedException(String.Format(
                                "Backend sent unrecognized response type: {0}",
                                (Char) message));
                    }
                }
            }
            finally
            {
                if (_sync.IsReadLockHeld)
                {
                    _sync.ExitReadLock();
                }
            }
        }

        /// <summary>Завершение записи буферизированных данных в сокет</summary>
        public void Flush()
        {
            try
            {
                _stream.Flush();
            }
            finally
            {
                if (_sync.IsWriteLockHeld)
                {
                    _sync.ExitWriteLock();
                }
            }
        }

        /// <summary>Закрытие потока</summary>
        public void Close()
        {
            _stream.Close();
        }

        /// <summary>Освобождение реурсов потока</summary>
        public void Dispose()
        {
            try
            {
                _stream?.Dispose();
                _sync?.Dispose();
            }
            finally
            {
                _stream = null;
                _sync = null;
            }
        }
        
        private NpgsqlCopyFormat ReadCopyHeader(Stream stream)
        {
            byte copyFormat = (byte) stream.ReadByte();
            Int16 numCopyFields = PGUtil.ReadInt16(stream);
            Int16[] copyFieldFormats = new Int16[numCopyFields];
            for (Int16 i = 0; i < numCopyFields; i++)
            {
                copyFieldFormats[i] = PGUtil.ReadInt16(stream);
            }
            return new NpgsqlCopyFormat(copyFormat, copyFieldFormats);
        }
        
        private byte[] NullTerminateArray(byte[] input)
        {
            byte[] output = new byte[input.Length + 1];
            input.CopyTo(output, 0);

            return output;
        }
    }
}