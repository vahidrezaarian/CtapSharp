// Ctap.Net
// Copyright (c) 2026 Vahidreza Arian
// 
// This file is part of Ctap.Net and is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

using LibUsbDotNet;
using LibUsbDotNet.Main;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace CtapDotNet.Transports.Nfc
{
    internal class CcidNfcSecurityKeyDevice : FidoSecurityKeyDevice
    {
        private readonly CcidSecurityKeyReaderDevice _readerDevice;

        public CcidNfcSecurityKeyDevice(UsbRegistry device)
        {
            _readerDevice = new CcidSecurityKeyReaderDevice(device);
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

    public static class UsbDeviceExtensions
    {
        public static bool IsCcidDevice(this UsbDevice usbDevice)
        {
            foreach (var iface in usbDevice.Configs[0].InterfaceInfoList)
            {
                if ((int)iface.Descriptor.Class == 0x0B)
                {
                    return true;
                }
            }
            return false;
        }

        public static int GetCcidInterfaceIndex(this UsbDevice usbDevice)
        {
            int indexCounter = 0;
            foreach (var iface in usbDevice.Configs[0].InterfaceInfoList)
            {
                if ((int)iface.Descriptor.Class == 0x0B)
                {
                    return indexCounter;
                }

                indexCounter++;
            }

            throw new Exception("This device has no CCID class interface!");
        }

        public static byte GetOutEndpointId(this UsbDevice usbDevice, int interfaceIndex)
        {
            var iface = usbDevice.Configs[0].InterfaceInfoList[interfaceIndex];
            foreach (var endpoint in iface.EndpointInfoList)
            {
                if (endpoint.Descriptor.Attributes == 0x02 && endpoint.Descriptor.EndpointID >= 0x00 && endpoint.Descriptor.EndpointID <= 0x7F)
                {
                    return endpoint.Descriptor.EndpointID;
                }
            }
            throw new Exception("The device has no OUT endpoint!");
        }

        public static byte GetInEndpointId(this UsbDevice usbDevice, int interfaceIndex)
        {
            var iface = usbDevice.Configs[0].InterfaceInfoList[interfaceIndex];
            foreach (var endpoint in iface.EndpointInfoList)
            {
                if (endpoint.Descriptor.Attributes == 0x02 && endpoint.Descriptor.EndpointID >= 0x80 && endpoint.Descriptor.EndpointID <= 0xFF)
                {
                    return endpoint.Descriptor.EndpointID;
                }
            }
            throw new Exception("The device has no IN endpoint!");
        }

        public static byte GetInterruptEndpointId(this UsbDevice usbDevice, int interfaceIndex)
        {
            var iface = usbDevice.Configs[0].InterfaceInfoList[interfaceIndex];
            foreach (var endpoint in iface.EndpointInfoList)
            {
                if (endpoint.Descriptor.Attributes == 0x03)
                {
                    return endpoint.Descriptor.EndpointID;
                }
            }
            throw new Exception("The device has no Interrupt endpoint!");
        }
    }

    internal class CcidSecurityKeyReaderDevice : IDisposable
    {
        private enum PcToReaderCommand
        {
            // Command to power on the ICC and retrieve the ATR
            IccPowerOn = 0x62,

            // Command to power off the ICC
            IccPowerOff = 0x63,

            // Command to get the status of the slot (e.g., card present or error state)
            GetSlotStatus = 0x65,

            // Command to transfer a block of data to/from the ICC
            XfrBlock = 0x6F,

            // Command to get the parameters of the ICC slot
            GetParameters = 0x6C,

            // Command to reset the parameters of the ICC slot to default
            ResetParameters = 0x6D,

            // Command to set custom parameters for the ICC slot
            SetParameters = 0x61,

            // Command for manufacturer-specific operations
            Escape = 0x6B,

            // Command to start or stop the clock signal for the ICC
            IccClock = 0x6E,

            // Command to send a T=0 APDU to the ICC
            T0Apdu = 0x6A,

            // Command to execute secure operations (e.g., PIN verification)
            Secure = 0x69,

            // Command to control mechanical features of the reader (e.g., card ejection)
            Mechanical = 0x71,

            // Command to abort an ongoing command
            Abort = 0x72,

            // Command to set the data rate and clock frequency for the ICC communication
            SetDataRateAndClockFrequency = 0x73
        }
        private enum ReaderToPcResponse
        {
            // Response to a data block transfer from the ICC to the host
            DataBlock = 0x80,

            // Response to a slot status query (provides status of the slot)
            SlotStatus = 0x81,

            // Response to a parameter retrieval request (ICC slot parameters)
            Parameters = 0x82,

            // Response to a manufacturer-specific command (escape command)
            Escape = 0x83,

            // Notification of a slot status change (e.g., card inserted/removed)
            NotifySlotChange = 0x50,

            // Indicates a hardware error in the reader
            HardwareError = 0x51
        }

        private readonly UsbRegistry _deviceUsbRegistry;
        private UsbDevice _usbDevice;
        private readonly int _inEndpoint;
        private readonly int _outEndpoint;
        private readonly CancellationTokenSource _cancellationToken;
        private byte _ccidCommandSequence;
        private readonly object _ccidSequenceLock = new object();

        private static readonly byte[] Fido2Aid = { 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01 };

        // CTAP-over-NFC (ISO7816) constants
        private const int MaxShortLc = 251;
        private const byte InsCtapMsg = 0x10;       // CTAP MSG
        private const byte InsGetNext = 0x11;       // CTAP GET NEXT RESPONSE

        public readonly string DeviceInfoString;

        public bool IsConnected
        {
            get
            {
                if (_usbDevice == null || _usbDevice.UsbRegistryInfo == null)
                {
                    return false;
                }

                return _usbDevice.UsbRegistryInfo.IsAlive;
            }
        }

        public string DevicePath
        {
            get
            {
                return _deviceUsbRegistry.DevicePath;
            }
        }

        public CcidSecurityKeyReaderDevice(UsbRegistry deviceUsbRegistry)
        {
            _deviceUsbRegistry = deviceUsbRegistry;
            if (!_deviceUsbRegistry.Open(out _usbDevice))
            {
                throw new Exception("Failed to open the USB device!");
            }

            var interfaceIndex = _usbDevice.GetCcidInterfaceIndex();
            _inEndpoint = _usbDevice.GetInEndpointId(interfaceIndex);
            _outEndpoint = _usbDevice.GetOutEndpointId(interfaceIndex);
            DeviceInfoString = $"{_usbDevice.Info.ProductString} - (Vendor ID: 0x{_usbDevice.Info.Descriptor.VendorID:X}, Product ID:0x{_usbDevice.Info.Descriptor.ProductID:X})";
            _cancellationToken = new CancellationTokenSource();
        }

        ~CcidSecurityKeyReaderDevice()
        {
            Dispose();
        }

        public void Dispose()
        {
            if (_usbDevice != null && _usbDevice.IsOpen)
            {
                _usbDevice?.Close();
                _usbDevice = null;
            }
            _cancellationToken?.Cancel();
        }

        public byte[] Send(byte[] data)
        {
            if (!TrySelectingFidoApplet())
                throw new Exception($"Failed to select the FIDO applet!");

            byte[] response = SendCtapChained(data);

            if (response == null || response.Length == 0)
                throw new Exception("Empty CTAP2 NFC response.");

            return response;
        }

        private byte[] CreateCcidDataPacket(PcToReaderCommand command, byte slotNumber, byte sequence, byte[] messageSpecificData = null, byte[] additionalData = null)
        {
            byte[] data;

            if (additionalData != null)
            {
                data = new byte[10 + additionalData.Length];
                data[1] = (byte)(additionalData.Length & 0xFF);
                data[2] = (byte)((additionalData.Length >> 8) & 0xFF);
                data[3] = (byte)((additionalData.Length >> 16) & 0xFF);
                data[4] = (byte)((additionalData.Length >> 24) & 0xFF);
            }
            else
            {
                data = new byte[10];
            }

            data[0] = (byte)command;
            data[5] = slotNumber;
            data[6] = sequence;

            if (messageSpecificData != null)
                Array.Copy(messageSpecificData, 0, data, 7, 3);

            if (additionalData != null)
                Array.Copy(additionalData, 0, data, 10, additionalData.Length);

            return data;
        }

        private byte[] ReadNextCcidMessage(UsbEndpointReader reader, int timeoutMs)
        {
            var first = new byte[64];
            var statusCode = reader.Read(first, timeoutMs, out int len);

            if (statusCode != ErrorCode.Success)
                throw new Exception($"USB reading failed. Error code: {(int)statusCode}");

            if (len < 10)
                throw new Exception($"Short CCID header with length of: {len} bytes");

            int dataLength =
                first[1] |
                (first[2] << 8) |
                (first[3] << 16) |
                (first[4] << 24);

            if (dataLength < 0 || dataLength > 65536)
                throw new Exception($"Invalid CCID dwLength={dataLength}. Header: {BitConverter.ToString(first, 0, Math.Min(len, 10)).Replace("-", " ")}");

            int total = 10 + dataLength;
            var full = new byte[total];

            int copy = Math.Min(len, total);
            Array.Copy(first, 0, full, 0, copy);

            int read = copy;
            while (read < total)
            {
                var chunk = new byte[Math.Min(64, total - read)];
                statusCode = reader.Read(chunk, timeoutMs, out int got);

                if (statusCode != ErrorCode.Success)
                    throw new Exception($"USB reading failed. Error code: {(int)statusCode}");

                if (got <= 0)
                    throw new Exception($"USB read 0 bytes!");

                Array.Copy(chunk, 0, full, read, got);
                read += got;
            }

            return full;
        }

        private byte[] SendCcidCommand(byte[] command)
        {
            if (command == null || command.Length < 10)
                throw new ArgumentException("CCID command must be at least 10 bytes.", nameof(command));

            if (_usbDevice == null || !_usbDevice.IsOpen)
            {
                if (!_deviceUsbRegistry.Open(out _usbDevice))
                    throw new Exception("Failed to open the USB device!");
            }

            var writer = _usbDevice.OpenEndpointWriter((LibUsbDotNet.Main.WriteEndpointID)_outEndpoint);
            var ec = writer.Write(command, 5000, out int written);
            if (ec != ErrorCode.Success)
                throw new Exception($"USB writing failed with status code {(int)ec}");

            var reader = _usbDevice.OpenEndpointReader((ReadEndpointID)_inEndpoint);

            byte expectedSeq = command[6];
            var expectedReaderResponseType = ReaderToPcResponse.DataBlock;
            if (command[0] == (byte)PcToReaderCommand.GetSlotStatus)
            {
                expectedReaderResponseType = ReaderToPcResponse.SlotStatus;
            }
            else if (command[0] == (byte)PcToReaderCommand.Escape)
            {
                expectedReaderResponseType = ReaderToPcResponse.Escape;
            }

            byte[] firstReadBuffer = null;

            // Phase 1: find first response matching (type, seq)
            for (int i = 0; i < 12; i++)
            {
                firstReadBuffer = ReadNextCcidMessage(reader, 5000);

                if (firstReadBuffer[0] == (byte)expectedReaderResponseType && firstReadBuffer[6] == expectedSeq)
                    break;

                firstReadBuffer = null;
            }

            if (firstReadBuffer == null)
                throw new Exception($"Did not receive expected CCID response (type=0x{(byte)expectedReaderResponseType:X2}, seq={expectedSeq}).");

            // Phase 2: handle Time Extension (cmdStatus==2)
            for (int ext = 0; ext < 30; ext++)
            {
                if (firstReadBuffer.Length >= 10)
                {
                    byte bStatus = firstReadBuffer[7];

                    // Inline decode: cmdStatus = bits 6..7
                    byte cmdStatus = (byte)((bStatus >> 6) & 0x03);

                    if (cmdStatus != 2)
                        return firstReadBuffer;
                }

                var secondReadBuffer = ReadNextCcidMessage(reader, 5000);
                if (secondReadBuffer[0] == (byte)expectedReaderResponseType && secondReadBuffer[6] == expectedSeq)
                {
                    firstReadBuffer = secondReadBuffer;
                    continue;
                }
            }

            throw new Exception("CCID command did not complete (time extension loop exceeded).");
        }

        private byte[] SendApdu(byte[] apdu)
        {
            if (apdu == null || apdu.Length == 0)
                throw new ArgumentException("APDU cannot be null or empty", nameof(apdu));

            if (_usbDevice == null || !_usbDevice.IsOpen)
            {
                if (!_deviceUsbRegistry.Open(out _usbDevice))
                    throw new Exception("Failed to open the USB device!");
            }

            byte seq;
            lock (_ccidSequenceLock)
            {
                seq = _ccidCommandSequence++;
            }

            var slotStatusResponse = SendCcidCommand(CreateCcidDataPacket(PcToReaderCommand.GetSlotStatus, 0, seq));

            if (slotStatusResponse.Length < 10)
                throw new Exception($"Truncated SlotStatus response ({slotStatusResponse.Length} bytes): {BitConverter.ToString(slotStatusResponse).Replace("-", " ")}");

            if (slotStatusResponse[0] != 0x81)
                throw new Exception($"Unexpected response type to GetSlotStatus: 0x{slotStatusResponse[0]:X2}. Full: {BitConverter.ToString(slotStatusResponse).Replace("-", " ")}");

            byte slot_bStatus = slotStatusResponse[7];
            byte slot_bError = slotStatusResponse[8];

            // Inline decode:
            byte slotIccStatus = (byte)(slot_bStatus & 0x03);
            byte slotCmdStatus = (byte)((slot_bStatus >> 6) & 0x03);

            if (slotCmdStatus == 1)
                throw new Exception($"GetSlotStatus failed. bStatus=0x{slot_bStatus:X2}, bError=0x{slot_bError:X2}");

            if (slotIccStatus == 2)
                throw new Exception("No card is present on the reader!");

            if (slotIccStatus == 1)
            {
                lock (_ccidSequenceLock) { seq = _ccidCommandSequence++; }
                var iccPowerOnResponse = SendCcidCommand(CreateCcidDataPacket(PcToReaderCommand.IccPowerOn, 0, seq));

                if (iccPowerOnResponse.Length < 10 || iccPowerOnResponse[0] != 0x80)
                    throw new Exception($"Unexpected response to IccPowerOn: {BitConverter.ToString(iccPowerOnResponse).Replace("-", " ")}");

                byte pwr_bStatus = iccPowerOnResponse[7];
                byte pwr_bError = iccPowerOnResponse[8];

                byte pwrIccStatus = (byte)(pwr_bStatus & 0x03);
                byte pwrCmdStatus = (byte)((pwr_bStatus >> 6) & 0x03);

                if (pwrCmdStatus == 1)
                    throw new Exception($"IccPowerOn failed. bStatus=0x{pwr_bStatus:X2}, bError=0x{pwr_bError:X2}");
            }

            lock (_ccidSequenceLock) { seq = _ccidCommandSequence++; }
            byte[] xfrMsgSpecific = { 0x0A, 0x00, 0x00 }; // bBWI=0x0A, wLevelParameter=0

            var apduCcidResp = SendCcidCommand(CreateCcidDataPacket(PcToReaderCommand.XfrBlock, 0, seq, xfrMsgSpecific, apdu));

            if (apduCcidResp.Length < 10)
                throw new Exception($"Truncated DataBlock response ({apduCcidResp.Length} bytes): {BitConverter.ToString(apduCcidResp).Replace("-", " ")}");

            if (apduCcidResp[0] != 0x80)
                throw new Exception($"Unexpected response type to XfrBlock: 0x{apduCcidResp[0]:X2}. Full: {BitConverter.ToString(apduCcidResp).Replace("-", " ")}");

            int responseDataLength =
                apduCcidResp[1] |
                (apduCcidResp[2] << 8) |
                (apduCcidResp[3] << 16) |
                (apduCcidResp[4] << 24);

            byte apdu_bStatus = apduCcidResp[7];
            byte apdu_bError = apduCcidResp[8];

            byte apduIccStatus = (byte)(apdu_bStatus & 0x03);
            byte apduCmdStatus = (byte)((apdu_bStatus >> 6) & 0x03);

            if (apduCmdStatus == 1)
                throw new Exception($"CCID XfrBlock failed. bStatus=0x{apdu_bStatus:X2}, bError=0x{apdu_bError:X2}");

            if (responseDataLength < 2)
                throw new Exception($"Invalid APDU response length in DataBlock: {responseDataLength}");

            int requiredLength = 10 + responseDataLength;
            if (apduCcidResp.Length < requiredLength)
                throw new Exception($"APDU DataBlock buffer too short. Expected {requiredLength}, got {apduCcidResp.Length}. Full: {BitConverter.ToString(apduCcidResp).Replace("-", " ")}");

            var apduResponseData = new byte[responseDataLength];
            Array.Copy(apduCcidResp, 10, apduResponseData, 0, responseDataLength);
            return apduResponseData;
        }

        private bool TrySelectingFidoApplet()
        {
            if (!IsConnected) return false;

            byte[] selectApdu = BuildShortApdu(0x00, 0xA4, 0x04, 0x00, Fido2Aid, le: 0x00);
            byte[] resp = SendApdu(selectApdu);

            if (resp == null || resp.Length < 2) return false;
            var sw = (ushort)((resp[resp.Length - 2] << 8) | resp[resp.Length - 1]);
            return sw == 0x9000;
        }

        private byte[] SendCtapChained(byte[] ctapMessage)
        {
            // ---- Command chaining with INS=0x10 ----
            int offset = 0;
            byte[] responseBytes = null;

            while (offset < ctapMessage.Length)
            {
                int remaining = ctapMessage.Length - offset;
                int chunkLen = Math.Min(MaxShortLc, remaining);
                bool more = (offset + chunkLen) < ctapMessage.Length;

                byte cla = (byte)(0x80 | (more ? 0x10 : 0x00)); // 0x90 for "more", 0x80 for last
                byte ins = InsCtapMsg;

                var chunk = new byte[chunkLen];
                Buffer.BlockCopy(ctapMessage, offset, chunk, 0, chunkLen);

                var apdu = BuildShortApdu(cla, ins, 0x00, 0x00, chunk, le: 0x00);
                responseBytes = SendApdu(apdu);

                if (responseBytes == null || responseBytes.Length < 2)
                    throw new Exception("Truncated APDU response during command chaining.");

                ushort swChunk = (ushort)((responseBytes[responseBytes.Length - 2] << 8) | responseBytes[responseBytes.Length - 1]);

                if (more)
                {
                    if (swChunk != 0x9000)
                        throw new Exception($"Card returned error during command chaining: 0x{swChunk:X4}");

                    responseBytes = null; // ignore intermediate data
                }

                offset += chunkLen;
            }

            if (responseBytes == null)
                throw new Exception("No response received for final chained APDU block.");

            // ---- Drain response chunks until SW=9000 ----
            MemoryStream ms = new MemoryStream();
            try
            {
                while (true)
                {
                    if (responseBytes.Length < 2)
                        throw new Exception("Truncated APDU response.");

                    ushort sw = (ushort)((responseBytes[responseBytes.Length - 2] << 8) | responseBytes[responseBytes.Length - 1]);
                    byte sw1 = (byte)(sw >> 8);
                    byte sw2 = (byte)(sw & 0xFF);

                    if (responseBytes.Length > 2)
                        ms.Write(responseBytes, 0, responseBytes.Length - 2);

                    if (sw == 0x9000)
                        break;

                    // CTAP GetNextResponse: 9100
                    if (sw == 0x9100)
                    {
                        var getNext = BuildShortApdu(0x80, InsGetNext, 0x00, 0x00, null, le: 0x00);
                        responseBytes = SendApdu(getNext);
                        continue;
                    }

                    // ISO7816 GET RESPONSE: 61xx
                    if (sw1 == 0x61)
                    {
                        int le = (sw2 == 0x00) ? 256 : sw2;
                        byte[] isoGet = { 0x00, 0xC0, 0x00, 0x00, (byte)(le & 0xFF) };
                        responseBytes = SendApdu(isoGet);
                        continue;
                    }

                    throw new Exception($"Card returned an error with status code: 0x{sw:X4}");
                }

                return ms.ToArray();
            }
            finally
            {
                ms.Dispose();
            }
        }

        private static byte[] BuildShortApdu(byte cla, byte ins, byte p1, byte p2, byte[] data, byte? le)
        {
            int dataLen = data?.Length ?? 0;
            if (dataLen > 251)
                throw new ArgumentOutOfRangeException(nameof(data), "Short APDU data cannot exceed 251 bytes.");

            bool hasData = dataLen > 0;
            bool hasLe = le.HasValue;

            int len = 4 + (hasData ? 1 + dataLen : 0) + (hasLe ? 1 : 0);
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
                apdu[idx++] = le.Value;

            return apdu;
        }

        public static IEnumerable<UsbRegistry> AllDevices
        {
            get
            {
                UsbDevice usbDevice = null;
                foreach (UsbRegistry device in UsbDevice.AllDevices)
                {
                    bool isFido = false;
                    try
                    {
                        if (device.Open(out usbDevice))
                        {
                            if (usbDevice.IsCcidDevice())
                            {
                                usbDevice.Close();
                                using (var ccidDevice = new CcidSecurityKeyReaderDevice(device))
                                {
                                    isFido = ccidDevice.TrySelectingFidoApplet();
                                }
                            }
                            else
                            {
                                usbDevice.Close();
                            }
                        }
                    }
                    catch (Exception)
                    {
                        try
                        {
                            usbDevice?.Close();
                        }
                        catch (Exception) { }
                    }
                    if (isFido)
                    {
                        yield return device;
                    }
                }
            }
        }
    }
}
