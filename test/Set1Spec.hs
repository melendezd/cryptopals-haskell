module Set1Spec where

import Test.Hspec
import Set1
import qualified Data.ByteString.Char8 as BC

spec :: Spec
spec = do
    describe "Set1.hexToBase64" $ do
        it "converts a hex bytestring to a base64 bytestring" $ do
            hexToBase64 hexStr `shouldBe` b64Str
                where hexStr = BC.pack "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
                      b64Str = BC.pack "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
