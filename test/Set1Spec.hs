module Set1Spec where

import Test.Hspec
import Set1
import qualified Data.ByteString.Char8 as BC
import Data.Char

spec :: Spec
spec = describe "Set1" $ do
    describe "hexToBase64" $ do
        it "converts a hex bytestring to a base64 bytestring" $ do
            let hexStr = BC.pack "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
            let b64Str = BC.pack "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
            hexToBase64 hexStr `shouldBe` b64Str
    describe "hexXor" $ do
        it "XOR's two equal-length hex bytestrings" $ do
            let str1 = BC.pack "1c0111001f010100061a024b53535009181c"
            let str2 = BC.pack "686974207468652062756c6c277320657965"
            let result = BC.pack "746865206b696420646f6e277420706c6179"
            hexXor str1 str2 `shouldBe` result
    describe "decryptEnglishSingleByteXor" $ do
        it "Decrypts an English message encrypted with a single-byte XOR cipher" $ do
            let str1 = "This is a string of English text."
            let str2 = "It was a long and stormy night..."
            let str1' = map toUpper . filter isAlpha $ str1
            let str2' = map toUpper . filter isAlpha $ str2
            let bs1 = BC.pack str1
            let bs2 = BC.pack str2
            -- Test decryptEnglishSingleByteXor on string XOR's with each possible byte
            mapM_ (uncurry shouldBe) 
                [(map toUpper . filter isAlpha . decryptEnglishSingleByteXor . (singleByteXor k) $ bs1 
                        , str1') | k <- [0..255]]
            mapM_ (uncurry shouldBe) 
                [(map toUpper . filter isAlpha . decryptEnglishSingleByteXor . (singleByteXor k) $ bs2
                        , str2') | k <- [0..255]]
    describe "keyRepeatingXor" $ do
        it "Encrypts a bytestring using key-repeating XOR" $ do
            let plain = BC.pack "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
            let cipher = fromHexWith id $ BC.pack "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
            keyRepeatingXor (BC.pack "ICE") plain `shouldBe` cipher
