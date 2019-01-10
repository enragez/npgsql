// created on 6/14/2002 at 7:56 PM

// Npgsql.NpgsqlState.cs
//
// Author:
//     Dave Joyner <d4ljoyn@yahoo.com>
//
//    Copyright (C) 2002 The Npgsql Development Team
//    npgsql-general@gborg.postgresql.org
//    http://gborg.postgresql.org/project/npgsql/projdisplay.php
//
// Permission to use, copy, modify, and distribute this software and its
// documentation for any purpose, without fee, and without a written
// agreement is hereby granted, provided that the above copyright notice
// and this paragraph and the following two paragraphs appear in all copies.
//
// IN NO EVENT SHALL THE NPGSQL DEVELOPMENT TEAM BE LIABLE TO ANY PARTY
// FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES,
// INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
// DOCUMENTATION, EVEN IF THE NPGSQL DEVELOPMENT TEAM HAS BEEN ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//
// THE NPGSQL DEVELOPMENT TEAM SPECIFICALLY DISCLAIMS ANY WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS
// ON AN "AS IS" BASIS, AND THE NPGSQL DEVELOPMENT TEAM HAS NO OBLIGATIONS
// TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.

using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Resources;
using System.Text;
using System.Threading;

namespace Npgsql
{
    ///<summary> This class represents the base class for the state pattern design pattern
    /// implementation.
    /// </summary>
    ///
    internal abstract partial class NpgsqlState
    {
        static byte[] NullTerminateArray(byte[] input)
        {
            byte[] output = new byte[input.Length + 1];
            input.CopyTo(output, 0);

            return output;
        }

        protected IEnumerable<IServerResponseObject> ProcessBackendResponses(NpgsqlConnector context)
        {
            NpgsqlEventLog.LogMethodEnter(LogLevel.Debug, CLASSNAME, "ProcessBackendResponses");

            using (new ContextResetter(context))
            {
                return context.Stream.ProcessBackendResponse(context, resman);
            }
        }
    }
    
    public enum BackEndMessageCode
    {
        IO_ERROR = -1, // Connection broken. Mono returns -1 instead of throwing an exception as ms.net does.

        CopyData = 'd',
        CopyDone = 'c',
        DataRow = 'D',

        BackendKeyData = 'K',
        CancelRequest = 'F',
        CompletedResponse = 'C',
        CopyDataRows = ' ',
        CopyInResponse = 'G',
        CopyOutResponse = 'H',
        EmptyQueryResponse = 'I',
        ErrorResponse = 'E',
        FunctionCall = 'F',
        FunctionCallResponse = 'V',

        AuthenticationRequest = 'R',

        NoticeResponse = 'N',
        NotificationResponse = 'A',
        ParameterStatus = 'S',
        PasswordPacket = ' ',
        ReadyForQuery = 'Z',
        RowDescription = 'T',
        SSLRequest = ' ',

        // extended query backend messages
        ParseComplete = '1',
        BindComplete = '2',
        PortalSuspended = 's',
        ParameterDescription = 't',
        NoData = 'n',
        CloseComplete = '3'
    }

    public enum AuthenticationRequestType
    {
        AuthenticationOk = 0,
        AuthenticationKerberosV4 = 1,
        AuthenticationKerberosV5 = 2,
        AuthenticationClearTextPassword = 3,
        AuthenticationCryptPassword = 4,
        AuthenticationMD5Password = 5,
        AuthenticationSCMCredential = 6,
        AuthenticationGSS = 7,
        AuthenticationGSSContinue = 8,
        AuthenticationSSPI = 9
    }
}
