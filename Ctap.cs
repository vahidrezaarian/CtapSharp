using CtapSharp.Transports;
using PeterO.Cbor;
using System;
using System.Collections.Generic;

namespace CtapSharp
{
    public static partial class Extensions
    {
        public static CBORObject ToCborObject(this byte[] data)
        {
            return CBORObject.DecodeFromBytes(data);
        }
    }

    public class Ctap: IDisposable
    {
        private readonly FidoSecurityKeyDevice _device;

        public Ctap (FidoSecurityKeyDevice device)
        {
            _device = device;
        }

        public void Dispose()
        {
            _device.Dispose();
        }

        public byte[] GetInfo()
        {
            var response = _device.Send(CreateCborPacket(CtapCborSubCommands.GetInfo));
            CheckResponse(CtapCborSubCommands.GetInfo, response);
            return ExtractDataFromResponse(response);
        }

        public byte[] GetPinRetries()
        {
            var packet = CreateCborPacket(CtapCborSubCommands.ClientPin, CBORObject.FromObject(new Dictionary<int, object>
            {
                { 1, 1 },
                { 2, 1 },
            }));

            var response = _device.Send(packet);
            CheckResponse(CtapCborSubCommands.ClientPin, response);
            return ExtractDataFromResponse(response);
        }

        public byte[] GetPinToken(byte[] pinHashEnc, CBORObject platformKeyAgreement, int pinProtocol)
        {
            var packet = CreateCborPacket(CtapCborSubCommands.ClientPin, CBORObject.FromObject(new Dictionary<int, object>
            {
                { 1, pinProtocol },
                { 2, 5 },
                { 3, platformKeyAgreement},
                { 6, pinHashEnc}
            }));

            var response = _device.Send(packet);
            CheckResponse(CtapCborSubCommands.ClientPin, response);
            return ExtractDataFromResponse(response);
        }

        public byte[] GetPinToken(byte[] pinHashEnc, byte[] platformKeyAgreement, int pinProtocol)
        {
            return GetPinToken(pinHashEnc, platformKeyAgreement.ToCborObject(), pinProtocol);
        }

        public byte[] GetKeyAgreement()
        {
            var packet = CreateCborPacket(CtapCborSubCommands.ClientPin, CBORObject.FromObject(new Dictionary<int, object>
            {
                { 1, 1 },
                { 2, 2 },
            }));

            var response = _device.Send(packet);
            CheckResponse(CtapCborSubCommands.ClientPin, response);
            return ExtractDataFromResponse(response);
        }

        public byte[] GetAssertion(string rpid, byte[] clientDataHash, CBORObject allowList = null, CBORObject extensions = null, CBORObject options = null, byte[] pinAuth = null, int pinProtocol = 1)
        {
            var request = new Dictionary<int, object>
            {
                { 1, rpid },
                { 2, clientDataHash }
            };
            if (allowList != null)
            {
                request[3] = allowList;
            }
            if (extensions != null)
            {
                request[4] = extensions;
            }
            if (options != null)
            {
                request[5] = options;
            }
            if (pinAuth != null)
            {
                request[6] = pinAuth;
                request[7] = pinProtocol;
            }
            return GetAssertion(CBORObject.FromObject(request));
        }

        public byte[] GetAssertion(string rpid, byte[] clientDataHash, byte[] allowList = null, byte[] extensions = null, byte[] options = null, byte[] pinAuth = null, int pinProtocol = 1)
        {
            return GetAssertion(rpid, clientDataHash, allowList?.ToCborObject(), extensions?.ToCborObject(), options?.ToCborObject(), pinAuth, pinProtocol);
        }

        public byte[] GetAssertion(CBORObject request)
        {
            var response = _device.Send(CreateCborPacket(CtapCborSubCommands.GetAssertion, request));
            CheckResponse(CtapCborSubCommands.GetAssertion, response);
            return ExtractDataFromResponse(response);
        }

        public byte[] GetAssertion(byte[] request)
        {
            return GetAssertion(request.ToCborObject());
        }

        public byte[] GetNextAssertion()
        {
            var response = _device.Send(CreateCborPacket(CtapCborSubCommands.GetNextAssertion));
            CheckResponse(CtapCborSubCommands.GetNextAssertion, response);
            return ExtractDataFromResponse(response);
        }

        public byte[] MakeCredential(byte[] clientDataHash, CBORObject rp, CBORObject user, CBORObject publickKeyCredParams, CBORObject excludeList = null, CBORObject extensions = null, CBORObject options = null, byte[] pinAuth = null, int pinProtocol = 1)
        {
            var request = new Dictionary<int, object>
            {
                { 1, clientDataHash },
                { 2, rp },
                { 3, user },
                { 4, publickKeyCredParams},
            };
            if (excludeList != null)
            {
                request[5] = excludeList;
            }
            if (extensions != null)
            {
                request[6] = extensions;
            }
            if (options != null)
            {
                request[7] = options;
            }
            if (pinAuth != null)
            {
                request[8] = pinAuth;
                request[9] = pinProtocol;
            }
            return MakeCredential(CBORObject.FromObject(request));
        }

        public byte[] MakeCredential(byte[] clientDataHash, byte[] rp, byte[] user, byte[] publickKeyCredParams, byte[] excludeList = null, byte[] extensions = null, byte[] options = null, byte[] pinAuth = null, int pinProtocol = 1)
        {
            return MakeCredential(clientDataHash, rp.ToCborObject(), user.ToCborObject(), publickKeyCredParams.ToCborObject(), excludeList?.ToCborObject(), extensions?.ToCborObject(), options?.ToCborObject(), pinAuth, pinProtocol);
        }

        public byte[] MakeCredential(CBORObject request)
        {
            var response = _device.Send(CreateCborPacket(CtapCborSubCommands.MakeCredential, request));
            CheckResponse(CtapCborSubCommands.MakeCredential, response);
            return ExtractDataFromResponse(response);
        }

        public byte[] MakeCredential(byte[] request)
        {
            return MakeCredential(request.ToCborObject());
        }

        public byte[] Reset()
        {
            var response = _device.Send(CreateCborPacket(CtapCborSubCommands.Reset));
            CheckResponse(CtapCborSubCommands.Reset, response);
            return ExtractDataFromResponse(response);
        }

        private byte[] ExtractDataFromResponse(byte[] response)
        {
            var data = new byte[response.Length - 1];
            Array.Copy(response, 1, data, 0, data.Length);
            return data;
        }

        private byte[] CreateCborPacket(CtapCborSubCommands subCommand, CBORObject cborObject = null)
        {
            if (cborObject == null)
            {
                byte[] shortPacket = { (byte)subCommand };
                return shortPacket;
            }

            var cborRequestBytes = cborObject.EncodeToBytes();
            var packet = new byte[cborRequestBytes.Length + 1];
            packet[0] = (byte)subCommand;

            Array.Copy(cborRequestBytes, 0, packet, 1, cborRequestBytes.Length);
            return packet;
        }

        private void CheckResponse(CtapCborSubCommands subCommand, byte[] response)
        {
            if (response[0] != 0)
            {
                var statusCode = (CtapStatusCode)response[0];
                if (byte.TryParse(statusCode.ToString(), out byte _))
                {
                    throw new CtapException(statusCode, $"{subCommand} failed in {_device.DeviceInfo.Name}. Status code: {statusCode:X}");
                }
                else
                {
                    throw new CtapException(statusCode, $"{subCommand} failed in {_device.DeviceInfo.Name}. Status code: {statusCode}");
                }
            }
        }
    }
}
