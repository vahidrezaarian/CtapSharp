// Ctap.Net
// Copyright (c) 2026 Vahidreza Arian
// 
// This file is part of Ctap.Net and is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

using PCSC;
using PCSC.Iso7816;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace CtapDotNet.Transports.Nfc
{
    internal class PcscNfcSecurityKeyDevice : FidoSecurityKeyDevice
    {
        private readonly PcscSecurityKeyReaderDevice _readerDevice;

        public PcscNfcSecurityKeyDevice(string readerName)
        {
            _readerDevice = new PcscSecurityKeyReaderDevice(readerName);
        }

        public override void Dispose()
        {
            _readerDevice.Dispose();
        }

        public override byte[] Send(byte[] data, CancellationTokenSource cancellationTokenSource = null, int timeout = -1)
        {
            return _readerDevice.Send(data);
        }
    }

    internal class PcscSecurityKeyReaderDevice: IDisposable
    {
        private static readonly byte[] FidoAid = new byte[]
        {
            0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01
        };

        private readonly SCardContext _scardContext;
        private readonly SCardReader _scardReader;
        private readonly string _readerName;

        public PcscSecurityKeyReaderDevice(string readerName)
        {
            _readerName = readerName;
            _scardContext = new SCardContext();
            _scardContext.Establish(SCardScope.System);
            _scardReader = new SCardReader(_scardContext);
        }

        public void Dispose()
        {
            _scardContext?.Dispose();
            _scardReader?.Dispose();
        }

        public static List<string> AllDevices
        {
            get
            {
                var readersList = new List<string>();
                using (var context = new SCardContext())
                {
                    context.Establish(SCardScope.System);

                    var readers = context.GetReaders();
                    if (readers != null && readers.Length > 0)
                    {
                        foreach (var readerName in readers)
                        {
                            using (var reader = new SCardReader(context))
                            {
                                var rc = reader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.Any);
                                if (rc != SCardError.Success)
                                {
                                    continue;
                                }

                                try
                                {
                                    TrySelectingFidoApplet(reader);
                                    readersList.Add(readerName);
                                }
                                catch { }
                                finally
                                {
                                    try { reader.Disconnect(SCardReaderDisposition.Leave); } catch { }
                                }
                            }
                        }
                    }
                }
                return readersList;
            }
        }

        private static void TrySelectingFidoApplet(SCardReader reader)
        {
            var receiveBuffer = new byte[256];

            var statucCode = reader.Transmit(
                SCardPCI.GetPci(reader.ActiveProtocol),
                new CommandApdu(IsoCase.Case4Short, reader.ActiveProtocol)
                {
                    CLA = 0x00,
                    INS = 0xA4,
                    P1 = 0x04,
                    P2 = 0x00,
                    Data = FidoAid
                }.ToArray(),
                ref receiveBuffer);

            if (statucCode != SCardError.Success)
            {
                throw new Exception($"PCSC transmit failed. Status code {statucCode}");
            }

            var response = new ResponseApdu(receiveBuffer, IsoCase.Case4Short, reader.ActiveProtocol);

            if (response.StatusWord != 0x9000)
            {
                throw new Exception($"FIDO applet selection failed. Status code: {response.StatusWord}");
            }
        }

        public static bool IsReaderStillConnected(string readerName)
        {
            try
            {
                var readers = AllDevices;
                if (readers == null || readers.Count == 0) return false;
                foreach (var r in readers)
                {
                    if (string.Equals(r, readerName, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to check if NFC reader is still connected. Error: {ex.Message}");
            }
        }

        public static void WaitForReaderToBeConnected(string readerName, CancellationToken cancellationToken, TimeSpan? timeout = null)
        {
            try
            {
                int counter = 0;
                while (true)
                {
                    if (IsReaderStillConnected(readerName))
                    {
                        return;
                    }

                    if (cancellationToken.IsCancellationRequested)
                    {
                        return;
                    }

                    counter++;
                    if (timeout != null && counter >= timeout.Value.TotalMilliseconds/100)
                    {
                        throw new TimeoutException();
                    }

                    Thread.Sleep(100);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failure in waiting for NFC reader connection. Error: {ex.Message}");
            }
        }

        public byte[] Send(byte[] packet)
        {
            byte[] response;

            var statusCode = _scardReader.Connect(_readerName, SCardShareMode.Shared, SCardProtocol.T0 | SCardProtocol.T1);
            if (statusCode != SCardError.Success)
                throw new Exception($"Failed to connect to the card. Status code: {statusCode}");

            try
            {
                TrySelectingFidoApplet(_scardReader);
                response = SendCtap(packet);
            }
            finally
            {
                try { _scardReader.Disconnect(SCardReaderDisposition.Leave); } catch { }
            }

            if (response == null || response.Length == 0)
                throw new Exception("Empty CTAP2 NFC response.");

            return response;
        }

        private byte[] SendCtap(byte[] ctapMessage)
        {
            const int MaxShortLc = 251;

            int offset = 0;

            byte[] responseBytes = null;

            while (offset < ctapMessage.Length)
            {
                int remaining = ctapMessage.Length - offset;
                int chunkLen = Math.Min(MaxShortLc, remaining);
                bool more = (offset + chunkLen) < ctapMessage.Length;

                byte cla = (byte)(0x80 | (more ? 0x10 : 0x00));
                byte ins = 0x10;
                byte p1 = 0x00;
                byte p2 = 0x00;

                var chunk = new byte[chunkLen];
                Buffer.BlockCopy(ctapMessage, offset, chunk, 0, chunkLen);

                var apdu = BuildShortApdu(cla, ins, p1, p2, chunk, le: 0x00);

                responseBytes = TransmitApdu(apdu);

                if (responseBytes == null || responseBytes.Length < 2)
                    throw new Exception("Truncated APDU response during command chaining.");

                ushort swChunk = (ushort)((responseBytes[responseBytes.Length - 2] << 8) | responseBytes[responseBytes.Length - 1]);
                if (more)
                {
                    if (swChunk != 0x9000)
                        throw new Exception($"Card returned error during command chaining: 0x{swChunk:X4}");
                    responseBytes = null;
                }

                offset += chunkLen;
            }

            // After last command block, responseBytes holds the response APDU to the final block.
            if (responseBytes == null)
                throw new Exception("No response received for final chained APDU block.");

            using (var ms = new MemoryStream())
            {
                while (true)
                {
                    if (responseBytes.Length < 2) throw new Exception("Truncated APDU response.");

                    ushort sw = (ushort)((responseBytes[responseBytes.Length - 2] << 8) | responseBytes[responseBytes.Length - 1]);
                    byte sw1 = (byte)(sw >> 8);
                    byte sw2 = (byte)(sw & 0xFF);

                    if (responseBytes.Length > 2)
                    {
                        ms.Write(responseBytes, 0, responseBytes.Length - 2);
                    }

                    if (sw == 0x9000) break;

                    // CTAP GetResponse Loop (9100)
                    if (sw == 0x9100)
                    {
                        // GET NEXT RESPONSE as SHORT APDU (no extended)
                        var getNext = BuildShortApdu(0x80, 0x11, 0x00, 0x00, null, le: 0x00);
                        responseBytes = TransmitApdu(getNext);
                        continue;
                    }

                    // ISO GetResponse Loop (61xx)
                    if (sw1 == 0x61)
                    {
                        int le = (sw2 == 0x00) ? 256 : sw2;
                        // Standard ISO GET RESPONSE: CLA=00, INS=C0
                        byte[] isoGet = new byte[] { 0x00, 0xC0, 0x00, 0x00, (byte)(le & 0xFF) };
                        responseBytes = TransmitApdu(isoGet);
                        continue;
                    }

                    throw new Exception($"Card returned an error. Status code: 0x{sw:X4}");
                }

                return ms.ToArray();
            }
        }

        private byte[] BuildShortApdu(byte cla, byte ins, byte p1, byte p2, byte[] data, byte? le)
        {
            int dataLen = data?.Length ?? 0;
            if (dataLen > 251) throw new ArgumentOutOfRangeException(nameof(data), "Short APDU data cannot exceed 255 bytes.");

            bool hasData = dataLen > 0;
            bool hasLe = le.HasValue;

            int len =
                4 +
                (hasData ? 1 + dataLen : 0) +
                (hasLe ? 1 : 0);

            var apdu = new byte[len];
            apdu[0] = cla;
            apdu[1] = ins;
            apdu[2] = p1;
            apdu[3] = p2;

            int idx = 4;

            if (hasData)
            {
                apdu[idx++] = (byte)dataLen;
                Buffer.BlockCopy(data, 0, apdu, idx, dataLen);
                idx += dataLen;
            }

            if (hasLe)
            {
                apdu[idx++] = le.Value;
            }

            return apdu;
        }

        private byte[] TransmitApdu(byte[] command)
        {
            IntPtr sendPci = SCardPCI.GetPci(_scardReader.ActiveProtocol);
            byte[] receiveBuffer = new byte[8192];
            int receiveLength = receiveBuffer.Length;
            var statusCode = _scardReader.Transmit(sendPci, command, command.Length, null, receiveBuffer, ref receiveLength);

            if (statusCode != SCardError.Success)
            {
                throw new Exception($"PCSC transmit failed. Status code: {statusCode}");
            }

            byte[] result = new byte[receiveLength];
            Buffer.BlockCopy(receiveBuffer, 0, result, 0, receiveLength);
            return result;
        }
    }
}
