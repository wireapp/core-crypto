//
// Wire
// Copyright (C) 2024 Wire Swiss GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.
//

import XCTest
import WireCoreCrypto

final class WireCoreCryptoTests: XCTestCase {

    func testTriggerMemoryCorruption() async throws {
        let fileManager = FileManager.default
        let temporaryPath = fileManager.temporaryDirectory.appending(component: UUID().uuidString)
        try fileManager.createDirectory(at: temporaryPath, withIntermediateDirectories: true)
        let databasePath = temporaryPath.appending(path: "corecrypto.db")
        let coreCrypto = try await coreCryptoDeferredInit(
            path: databasePath.absoluteString,
            key: "secret",
            ciphersuites: [1],
            nbKeyPackage: nil
        )

        let clientId = "\(UUID().uuidString):client123@example.com"
        var enrollment: E2eiEnrollment? = try await coreCrypto.e2eiNewEnrollment(
            clientId: clientId,
            displayName: "display",
            handle: "handle",
            team: nil,
            expirySec: 90_000,
            ciphersuite: 1
        )
        _  = try await enrollment?.checkOrderResponse(order: orderResponse.data(using: .utf8)!)
        _ = try await coreCrypto.e2eiMlsInitOnly(enrollment: enrollment!, certificateChain: certificateChain, nbKeyPackage: nil)
        enrollment = nil
    }


    let orderResponse = """
{
  "status": "ready",
  "finalize": "https://stepca:32769/acme/wire/order/iq3FmbOOTm51xcQ2piXHYXey2A40r4Wb/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\\"client-id\\":\\"wireapp://lYPMMhxlQyiJHg7f0X4tTg!f92c673e9c08f466@wire.com\\",\\"handle\\":\\"wireapp://%40alice_wire@wire.com\\",\\"name\\":\\"Alice Smith\\",\\"domain\\":\\"wire.com\\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\\"handle\\":\\"wireapp://%40alice_wire@wire.com\\",\\"name\\":\\"Alice Smith\\",\\"domain\\":\\"wire.com\\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32769/acme/wire/authz/33y8eTP1jgI5pwuOxZvh9F0ZlK9gW50u",
    "https://stepca:32769/acme/wire/authz/6v5MnzQwBvPXGcEfetxPPprCqBsbIKnH"
  ],
  "expires": "2024-03-27T11:03:32Z",
  "notBefore": "2024-03-26T11:03:32.835172Z",
  "notAfter": "2034-03-24T11:03:32.835172Z"
}
"""
    let certificateChain = "-----BEGIN CERTIFICATE-----\nMIICGjCCAb+gAwIBAgIQOIXuc1ZqKVU80JrvS88GJTAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nNDAzMjYxMTAzMzJaFw0zNDAzMjQxMTAzMzJaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhALIGmmgI9uM+SmwBJCEy\nieZ8JzSbVE0uCp7TdR4AJTzro4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\nDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQURcXiKoLlNpLiXmwBekJHo2HASgIwHwYD\nVR0jBBgwFoAU9icm15FoSZn3PDB0hOHjILRHf+gwaQYDVR0RBGIwYIYgd2lyZWFw\ncDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly9sWVBNTWh4bFF5\naUpIZzdmMFg0dFRnJTIxZjkyYzY3M2U5YzA4ZjQ2NkB3aXJlLmNvbTAdBgwrBgEE\nAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSQAwRgIhAIIi1H9G\nBwtbctuv0iKgU5LXx6rdYNXe1IBfyxsSQSFTAiEA/FG6Q6pqalATcHck5lu8HVG9\nKGZb/i+Ne9YcjKtJiww=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV6gAwIBAgIQVYvujgrLroo+FS47z7V9XTAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMzI2MTEw\nMzMxWhcNMzQwMzI0MTEwMzMxWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPcL\nftRCDLjpfvz3lwIK77AyR9jDhEAnzhN4F5GGmywORWHurYNjYavpc65kqq5VGKVN\nhD3j3atDujY8p8nfvg6jZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBT2JybXkWhJmfc8MHSE4eMgtEd/6DAfBgNVHSMEGDAW\ngBQ06fjoy0xr5Iz05d3TrZXmvrx4JDAKBggqhkjOPQQDAgNIADBFAiEAsvMotnAG\n2KEaaweGSn5u2UTNl6cYwcdci86ys8DHgFICICGWmlBUOo9TB/9SHhE4eguU57h6\n1raQVZReG6vgjxvv\n-----END CERTIFICATE-----\n"
}
