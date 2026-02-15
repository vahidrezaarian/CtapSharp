# CtapSharp
.NET client library for FIDO2/CTAP 2.0 authenticators over USB HID and NFC transports.  Implements core CTAP commands: authenticatorGetInfo, authenticatorGetAssertion, authenticatorMakeCredential, clientPin, and more.  Interact directly with security keys, passkeys, and FIDO2 hardware tokens from your .NET applications.

## Installation

Install via NuGet:

```bash
dotnet add package CtapSharp
```

Or in your .csproj:
```XML
<PackageReference Include="CtapSharp" Version="1.0.0" />
```

The latest version: https://www.nuget.org/packages/CtapSharp/1.0.0

## How to use
You simply need to look for a FIDO security key device, choose one and create an object of Ctap class using the found device. Then send the CTAP packets to the selected device.
```C#
foreach (var device in FidoSecurityKeyDevices.AllDevices)
{
    using (var ctap = new Ctap(device)) // Make sure the ctap object is disposed when finished
    {
        var securityKeyInfo = ctap.GetInfo().ToCborObject();
    }
}
```