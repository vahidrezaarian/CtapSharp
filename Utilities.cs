// Ctap.Net
// Copyright (c) 2026 Vahidreza Arian
// 
// This file is part of Ctap.Net and is licensed under the MIT license.
// See LICENSE file in the project root for full license information.

using PeterO.Cbor;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CtapDotNet
{
    public enum CtapStatusCode
    {
        OK = 0x00, // Indicates successful response
        CTAP1_ERR_INVALID_COMMAND = 0x01, // The command is not a valid CTAP command
        CTAP1_ERR_INVALID_PARAMETER = 0x02, // The command included an invalid parameter
        CTAP1_ERR_INVALID_LENGTH = 0x03, // Invalid message or item length
        CTAP1_ERR_INVALID_SEQ = 0x04, // Invalid message sequencing
        CTAP1_ERR_TIMEOUT = 0x05, // Message timed out
        CTAP1_ERR_CHANNEL_BUSY = 0x06, // Channel busy
        CTAP1_ERR_LOCK_REQUIRED = 0x0A, // Command requires channel lock
        CTAP1_ERR_INVALID_CHANNEL = 0x0B, // Command not allowed on this cid
        CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11, // Invalid/unexpected CBOR error
        CTAP2_ERR_INVALID_CBOR = 0x12, // Error when parsing CBOR
        CTAP2_ERR_MISSING_PARAMETER = 0x14, // Missing non-optional parameter
        CTAP2_ERR_LIMIT_EXCEEDED = 0x15, // Limit for number of items exceeded
        CTAP2_ERR_UNSUPPORTED_EXTENSION = 0x16, // Unsupported extension
        CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19, // Valid credential found in the exclude list
        CTAP2_ERR_PROCESSING = 0x21, // Processing (Lengthy operation is in progress)
        CTAP2_ERR_INVALID_CREDENTIA = 0x22, // Credential not valid for the authenticator
        CTAP2_ERR_USER_ACTION_PENDING = 0x23, // Authentication is waiting for user interaction
        CTAP2_ERR_OPERATION_PENDING = 0x24, // Processing, lengthy operation is in progress
        CTAP2_ERR_NO_OPERATIONS = 0x25, // No request is pending
        CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26, // Authenticator does not support requested algorithm
        CTAP2_ERR_OPERATION_DENIED = 0x27, // Not authorized for requested operation
        CTAP2_ERR_KEY_STORE_FULL = 0x28, // Internal key storage is full
        CTAP2_ERR_NO_OPERATION_PENDING = 0x2A, // No outstanding operations
        CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B, // Unsupported option
        CTAP2_ERR_INVALID_OPTION = 0x2C, // Not a valid option for current operation
        CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D, // Pending keep alive was cancelled
        CTAP2_ERR_NO_CREDENTIALS = 0x2E, // No valid credentials provided
        CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F, // Timeout waiting for user interaction
        CTAP2_ERR_NOT_ALLOWED = 0x30, // Continuation command, such as, authenticatorGetNextAssertion not allowed
        CTAP2_ERR_PIN_INVALID = 0x31, // PIN Invalid
        CTAP2_ERR_PIN_BLOCKED = 0x32, // PIN Blocked
        CTAP2_ERR_PIN_AUTH_INVALID = 0x33, // PIN authentication,pinAuth, verification failed
        CTAP2_ERR_PIN_AUTH_BLOCKED = 0x34, // PIN authentication,pinAuth, blocked. Requires power recycle to reset
        CTAP2_ERR_PIN_NOT_SET = 0x35, // No PIN has been set
        CTAP2_ERR_PIN_REQUIRED = 0x36, // PIN is required for the selected operation
        CTAP2_ERR_PIN_POLICY_VIOLATION = 0x37, // PIN policy violation. Currently only enforces minimum length
        CTAP2_ERR_PIN_TOKEN_EXPIRED = 0x38, // pinToken expired on authenticator
        CTAP2_ERR_REQUEST_TOO_LARGE = 0x39, // Authenticator cannot handle this request due to memory constraints
        CTAP2_ERR_ACTION_TIMEOUT = 0x3A, // The current operation has timed out
        CTAP2_ERR_UP_REQUIRED = 0x3B, // User presence is required for the requested operation
        CTAP1_ERR_OTHER = 0x7F, // Other unspecified error
        CTAP2_ERR_SPEC_LAST = 0xDF, // CTAP 2 spec last error
        CTAP2_ERR_EXTENSION_FIRST = 0xE0, // Extension specific error
        CTAP2_ERR_EXTENSION_LAST = 0xEF, // Extension specific error
        CTAP2_ERR_VENDOR_FIRST = 0xF0, // Vendor specific error
        CTAP2_ERR_VENDOR_LAST = 0xFF, // Vendor specific error
    }

    public enum CtapCborSubCommands
    {
        MakeCredential = 0x01,
        GetAssertion = 0x02,
        GetInfo = 0x04,
        GetNextAssertion = 0x08,
        ClientPin = 0x06,
        Reset = 0x07,
    }

    public class ProcessAbortedException : Exception
    {
        public ProcessAbortedException(string message)
            : base(message)
        {
        }
    }

    public class CtapException : Exception
    {
        public readonly CtapStatusCode StatusCode;
        public CtapException(CtapStatusCode statusCode, string message)
            : base(message)
        {
            StatusCode = statusCode;
        }
    }

    public static partial class Extensions
    {
        public static string ToBase64UrlString(this byte[] data)
        {
            return Utilities.ConvertByteArrayToBase64UrlString(data);
        }

        public static byte[] ToByteArrayFromBase64UrlString(this string data)
        {
            return Utilities.ConvertBase64UrlStringToByteArray(data);
        }

        public static string ToBase64String(this byte[] data)
        {
            return Utilities.ConvertByteArrayToBase64String(data);
        }

        public static byte[] ToByteArrayFromBase64String(this string data)
        {
            return Utilities.ConvertBase64StringToByteArray(data);
        }

        public static string ToHexString(this byte[] data)
        {
            return Utilities.ConvertByteArrayToHexString(data);
        }

        public static byte[] ToByteArrayFromHexString(this string data)
        {
            return Utilities.ConvertHexStringToByteArray(data);
        }

        public static byte[] ComputeSha256(this byte[] data)
        {
            return Utilities.ComputeSha256(data);
        }

        public static string ComputeSha256(this string data)
        {
            return Utilities.ComputeSha256(data);
        }

        public static ECParameters ToElipticCurveParameters(this CBORObject key)
        {
            var point = new ECPoint
            {
                X = key[-2].GetByteString(),
                Y = key[-3].GetByteString()
            };

            return new ECParameters
            {
                Q = point,
                Curve = ECCurve.NamedCurves.nistP256
            };
        }
    }

    public static class Utilities
    {
        public static byte[] GetRandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        public static string ConvertByteArrayToHexString(byte[] byteArray)
        {
            return BitConverter.ToString(byteArray).Replace("-", "");
        }

        public static byte[] ConvertHexStringToByteArray(string hex)
        {
            int length = hex.Length;
            if (length % 2 != 0)
                throw new ArgumentException("Hex string must have an even number of characters.");

            byte[] byteArray = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
            {
                byteArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return byteArray;
        }

        public static string ConvertByteArrayToBase64UrlString(byte[] data)
        {
            string base64 = Convert.ToBase64String(data);
            string base64Url = base64.Replace('+', '-')
                                     .Replace('/', '_')
                                     .TrimEnd('=');

            return base64Url;
        }

        public static byte[] ConvertBase64UrlStringToByteArray(string data)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentNullException(nameof(data));

            string base64 = data
                .Replace('-', '+')
                .Replace('_', '/');

            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }

            return Convert.FromBase64String(base64);
        }

        public static string ConvertByteArrayToBase64String(byte[] data)
        {
            return Convert.ToBase64String(data, 0, data.Length);
        }

        public static byte[] ConvertBase64StringToByteArray(string data)
        {
            return Convert.FromBase64String(data);
        }

        public static string ConvertHexStringToBase64String(string data)
        {
            var bytes = ConvertHexStringToByteArray(data);
            return Convert.ToBase64String(bytes, 0, bytes.Length);
        }

        public static string ConvertBase64StringToHexString(string data)
        {
            return ConvertByteArrayToHexString(Convert.FromBase64String(data));
        }

        public static string ComputeSha256(string data)
        {
            var hash = SHA256.Create();
            var dataBytes = Encoding.UTF8.GetBytes(data);
            return hash.ComputeHash(dataBytes).ToHexString();
        }

        public static byte[] ComputeSha256(byte[] data)
        {
            var hash = SHA256.Create();
            return hash.ComputeHash(data);
        }

        public static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] iv, PaddingMode padding = PaddingMode.None)
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = padding;
                ICryptoTransform decryptor = aes.CreateDecryptor(key, iv);
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (MemoryStream output = new MemoryStream())
                        {
                            cs.CopyTo(output);
                            return output.ToArray();
                        }
                    }
                }
            }
        }

        public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv, PaddingMode padding = PaddingMode.None)
        {
            byte[] encrypted;
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Padding = padding;
                ICryptoTransform encryptor = aes.CreateEncryptor(key, iv);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                    }
                    encrypted = ms.ToArray();
                }
            }
            return encrypted;
        }
    }
}
