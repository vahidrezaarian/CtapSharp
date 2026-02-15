// Ctap.Net
// Copyright (c) 2026 Vahidreza Arian
// 
// This file is part of Ctap.Net and is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

using HidSharp;
using System;
using System.Collections.Generic;
using System.Threading;

namespace CtapDotNet.Transports.Usb
{
    internal class UsbSecurityKeyDevice: FidoSecurityKeyDevice
    {
        private readonly byte[] _channelId;
        private readonly UsbFidoHidDevice _device;

        public UsbSecurityKeyDevice(HidDevice device)
        {
            _device = new UsbFidoHidDevice(device);
            _device.Open();
            _channelId = GetChannelId();
        }

        public override void Dispose()
        {
            _device.Close();
        }

        public override byte[] Send(byte[] data, CancellationTokenSource cancellationTokenSource = null, int timeout = -1)
        {
            var requestPacket = new byte[data.Length + 8];
            Array.Copy(_channelId, 0, requestPacket, 1, 4);
            requestPacket[5] = 0x90;
            requestPacket[6] = (byte)(data.Length >> 8);
            requestPacket[7] = (byte)(data.Length & 0xff);
            Array.Copy(data, 0, requestPacket, 8, data.Length);
            _device.Write(requestPacket);
            var (Data, Length) = _device.Read(cancellationTokenSource);
            byte[] response = new byte[Length];
            Array.Copy(Data, 0, response, 0, Length);
            return response;
        }

        private byte[] GetChannelId()
        {
            byte[] initPackt = { 0x00, 0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            var nonce = Utilities.GetRandomBytes(8);
            Array.Copy(nonce, 0, initPackt, 8, 8);

            _device.Write(initPackt);
            var initResponse = _device.Read(null, timeout: 3000);
            for (int i = 0; i < nonce.Length; i++)
            {
                if (nonce[i] != initResponse.Data[i])
                {
                    throw new Exception("Failed to initialize the USB security key. Error: Invalid init response!");
                }
            }

            var channelId = new byte[4];
            Array.Copy(initResponse.Data, 8, channelId, 0, 4);
            return channelId;
        }
    }

    internal class UsbFidoHidDevice
    {
        readonly HidDevice _device;
        HidStream _stream;

        public UsbFidoHidDevice(HidDevice device)
        {
            _device = device;
        }

        public void Open(bool recursiveCall = false)
        {
            try
            {
                _stream = _device.Open();
            }
            catch (Exception e)
            {
                if (!recursiveCall && IsDeviceStillConnected(_device))
                {
                    Close();
                    Thread.Sleep(1000);
                    Open(true);
                    return;
                }
                Close();
                if (recursiveCall)
                {
                    throw new Exception($"Failed to open the HID device. Error: {e.Message}");
                }
                else
                {
                    if (IsDeviceStillConnected(_device))
                    {
                        throw new Exception($"Failed to open the HID device. Error: {e.Message}");
                    }
                    else
                    {
                        throw new Exception($"Failed to open the HID device. Error: Device is not connected! Exception message: {e.Message}");
                    }
                }
            }
        }

        public void Close()
        {
            try
            {
                _stream?.Close();
            }
            catch (Exception) { }

            try
            {
                _stream?.Dispose();
            }
            catch (Exception) { }
        }

        public void Write(byte[] data)
        {
            try
            {
                if (_device == null)
                {
                    throw new InvalidOperationException("Device not initialized.");
                }

                if (_stream == null || !_stream.CanRead)
                {
                    _stream = _device.Open();
                }

                var outputReportBuffer = new byte[65];

                if (data.Length <= 65)
                {
                    Array.Copy(data, outputReportBuffer, data.Length);
                    _stream.Write(outputReportBuffer, 0, outputReportBuffer.Length);
                }
                else
                {
                    var listOfPacketsToWrite = new List<byte[]>();
                    var channelId = new byte[4];
                    var initialPacket = new byte[65];
                    Array.Copy(data, initialPacket, 65);
                    Array.Copy(data, 1, channelId, 0, 4);
                    listOfPacketsToWrite.Add(initialPacket);
                    int extractedDataLength = 65;
                    int remainingDataLength = data.Length - 65;

                    byte index = 0;
                    while (remainingDataLength > 0)
                    {
                        var tmpBuffer = new byte[65];
                        tmpBuffer[0] = 0;
                        // Copying the channel ID
                        Array.Copy(channelId, 0, tmpBuffer, 1, 4);
                        tmpBuffer[5] = index;
                        // Extracting the bytes from the buffer
                        var maxPermittedDataToExtract = 65 - 6;
                        int dataLengthToExtract = maxPermittedDataToExtract;
                        if (remainingDataLength <= maxPermittedDataToExtract)
                            dataLengthToExtract = remainingDataLength;
                        Array.Copy(data, extractedDataLength, tmpBuffer, 6, dataLengthToExtract);
                        // Updating the variables
                        extractedDataLength = extractedDataLength + dataLengthToExtract;
                        remainingDataLength = remainingDataLength - dataLengthToExtract;
                        index++;
                        // Adding the secondary packet to the list
                        listOfPacketsToWrite.Add(tmpBuffer);
                    }

                    foreach (var packet in listOfPacketsToWrite)
                    {
                        Array.Copy(packet, outputReportBuffer, packet.Length);
                        _stream.Write(outputReportBuffer, 0, outputReportBuffer.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to write to HID device. Error: {ex.Message}");
            }
        }

        public (byte[] Data, int Length) Read(CancellationTokenSource cancellationToken, int timeout = 10000, bool recursive = false)
        {
            try
            {
                if (_device == null)
                {
                    throw new InvalidOperationException("Device not initialized.");
                }

                if (_stream == null || !_stream.CanRead)
                {
                    _stream = _device.Open();
                }

                byte[] result;
                var inputReportBuffer = new byte[65];
                _stream.ReadTimeout = timeout;
                int bytesRead;

                try
                {
                    do
                    {
                        bytesRead = _stream.Read(inputReportBuffer, 0, inputReportBuffer.Length);
                        if (cancellationToken != null && cancellationToken.IsCancellationRequested)
                        {
                            Close();
                            throw new ProcessAbortedException("Process cancelled!");
                        }
                    }
                    while (inputReportBuffer[5] == 0xbb);
                }
                catch (ProcessAbortedException ex)
                {
                    throw new ProcessAbortedException(ex.Message);
                }
                catch (Exception ex)
                {
                    if (recursive)
                    {
                        throw new Exception(ex.Message);
                    }
                    else
                    {
                        _stream.Close();
                        _stream.Dispose();
                        return Read(cancellationToken, timeout, true);
                    }
                }

                int sizeOfReceivingData = inputReportBuffer[6] << 8 | inputReportBuffer[7];

                int sizeofResultBuffer = (int)Math.Ceiling((double)sizeOfReceivingData / 65) * 65;
                result = new byte[sizeofResultBuffer];
                Array.Copy(inputReportBuffer, 8, result, 0, bytesRead - 8);

                if (sizeOfReceivingData <= (bytesRead - 8))
                {
                    return (result, sizeOfReceivingData);
                }

                int allBytesRead = bytesRead - 8;
                while (allBytesRead < sizeOfReceivingData)
                {
                    bytesRead = _stream.Read(inputReportBuffer, 0, inputReportBuffer.Length);
                    int extractingDataLength = bytesRead - 6;
                    if ((result.Length - allBytesRead) < 65)
                    {
                        extractingDataLength = result.Length - allBytesRead;
                    }
                    Array.Copy(inputReportBuffer, 6, result, allBytesRead, extractingDataLength);
                    allBytesRead += (bytesRead - 6);
                }

                return (result, sizeOfReceivingData);
            }
            catch (ProcessAbortedException ex)
            {
                throw new ProcessAbortedException(ex.Message);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to read the HID device. Error: {ex.Message}");
            }
        }

        public static bool IsDeviceStillConnected(HidDevice device)
        {
            try
            {
                foreach (var dev in AllDevices)
                {
                    if (dev.DevicePath == device.DevicePath)
                    {
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to check if HID device is still connected. Error: {ex.Message}");
            }
        }

        public static bool IsDeviceStillConnected(string devicePath, out HidDevice device)
        {
            device = null;
            foreach (var d in AllDevices)
            {
                if (d.DevicePath == devicePath)
                {
                    device = d;
                    return true;
                }
            }
            return false;
        }

        public static bool IsDeviceStillConnected(string devicePath)
        {
            foreach (var d in AllDevices)
            {
                if (d.DevicePath == devicePath)
                {
                    return true;
                }
            }
            return false;
        }

        public static void WaitForDeviceToBeConnected(HidDevice device, CancellationToken cancellationToken)
        {
            try
            {
                while (true)
                {
                    foreach (var dev in AllDevices)
                    {
                        if (dev.DevicePath == device.DevicePath)
                        {
                            return;
                        }
                    }

                    if (cancellationToken.IsCancellationRequested)
                    {
                        return;
                    }

                    Thread.Sleep(100);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failure in waiting for device reconnection. Error: {ex.Message}");
            }
        }

        public static IEnumerable<HidDevice> AllDevices
        {
            get
            {
                var devices = DeviceList.Local.GetHidDevices();
                foreach (var dev in devices)
                {
                    var rreportDescriptorItems = dev.GetReportDescriptor().DeviceItems;
                    foreach (var item in rreportDescriptorItems)
                    {
                        foreach (var usage in item.Usages.GetAllValues())
                        {
                            if (usage == 4056940545)
                            {
                                if (dev.TryOpen(out HidStream tmpDeviceStream))
                                {
                                    tmpDeviceStream?.Close();
                                    yield return dev;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
