// HexaLocker.yar
// Copyright (C) 2024 - Synacktiv, Théo Letailleur
// contact@synacktiv.com
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

rule Windows_Ransomware_HexaLocker
{
    meta:
        author = "Theo Letailleur, Synacktiv"
        source = "Synacktiv"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        category = "MALWARE"
        malware = "HexaLocker"
        description = "Yara rule that detects Windows HexaLocker ransomware (08.2024)"
        samples = "87c1869871e9be8adaacb41a16c8fff691f86591416a592a77e308c4b7c041be, be759e58413431dbe40d29ea5e399b1ebbfe75847c19a5a8f2610dab9f78ca8b, 87f11be87275147a118544b10396c932dfd7e244cf07826d2707561c8e0f25e8"

    strings:
        $argon2 = "golang.org/x/crypto/argon2.deriveKey"
        $sendDataGet = "method=new&hwid=%s&ip=%s&computername=%s&password=%s&sel=%s"
        $aesgcm = "crypto/cipher.newGCMWithNonceAndTagSize"
        $extension = ".hexalocker"

    condition:
        uint16(0) == 0x5a4d and filesize < 9000000 and filesize > 5000000 and (
            all of them
        )
}
