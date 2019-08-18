module Set1 
  ( fromHexWith,
    hexToBase64,
    hexXor,
    singleByteXor,
    decryptEnglishSingleByteXor,
    repeatingKeyXor,
    hammingDistance,
    findVigenereKeySize,
    getChallengeSixText,
    challengeSixNumBlocks,
    challengeSixRange
  )
where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64
import Data.Word
import Data.Bits
import Data.Either
import Data.Char
import Util (minWith)
import System.IO
import Control.Applicative
import Data.List (genericLength, transpose)

----- Useful utilities not specific to any challenge -----

-- | Applies a raw bytestring function to a hex bytestring.
-- | Returns the resulting hex bytestring.
onHex :: (B.ByteString -> B.ByteString) -> B.ByteString -> B.ByteString
onHex f = B16.encode . f . fst . B16.decode

-- | Applies a 2-argument raw bytestring function to a hex bytestring.
-- | Returns the resulting hex bytestring.
onHex2 :: (B.ByteString -> B.ByteString -> B.ByteString) -> B.ByteString -> B.ByteString -> B.ByteString
onHex2 f bs1 bs2 = B16.encode $ f (unHex bs1) (unHex bs2)
    where unHex = fst . B16.decode

-- | Applies a raw bytestring function to a hex bytestring.
-- | Returns the raw bytestring.
fromHexWith :: (B.ByteString -> a) -> B.ByteString -> a
fromHexWith f = f . fst . B16.decode

-- | Applies a raw bytestring function to a base64 bytestring.
-- | Returns the raw bytestring.
fromB64With :: (B.ByteString -> a) -> B.ByteString -> a
fromB64With f = f . (fromRight B.empty) . B64.decode


----------------------------------------------------------
----------------------------------------------------------
----------------------------------------------------------

--- Challenge 1: Convert hex string to base64 string ---

-- | Convert a hex bytestring to a base64 bytestring
hexToBase64 :: B.ByteString -> B.ByteString
hexToBase64 = B64.encode . fst . B16.decode

--- Challenge 2: XOR two equal-length bytestrings ---

-- | XOR's two hex bytestrings.
-- | If the bytestrings have unequal length, the longer one is truncated to match
-- | the length of the shorter one.
hexXor :: B.ByteString -> B.ByteString -> B.ByteString
hexXor = onHex2 (\str1 str2 -> B.pack $ B.zipWith xor str1 str2)

    
--- Challenge 3: Single-byte XOR ---
{-
    Challenge:
    The hex-encoded string challengeThreeCode has been XOR'd against a single character.
    Find the key, decrypt the message.
-}

englishAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
englishCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ,./<>?;':\"[]\\{}|`-=~!@#$%^&*()_+\n"

-- | The sample code give in Challenge 3
challengeThreeCode :: B.ByteString
challengeThreeCode = BC.pack "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

-- | XOR's every byte in bytestring with the key
singleByteXor :: Word8 -> B.ByteString -> B.ByteString
singleByteXor key = B.map (xor key)

-- | Calculates the relative frequencies of each letter of the English alphabet 
-- | as they appear in the input string.
getAlphaFrequencies :: (Floating r) => String -> [r]
getAlphaFrequencies str = [freq letter str' | letter <- englishAlphabet]
    where str' = map toUpper . filter isAlpha $ str
          freq :: (Eq a, Fractional b) => a -> [a] -> b
          freq x xs = (fromIntegral (length $ filter (==x) xs)) / (fromIntegral (length xs))

-- | Relative frequencies of each letter in the alphabet, somewhat representative
-- | of the English language.
englishAlphaFrequencies :: (Fractional r) => [r]
englishAlphaFrequencies = fmap (/100) [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074]
    
-- | Calculates the distance between an input string's letter frequency vector and the letter
-- | frequency vector for English text, and adds a skew depending on how many "weird" characters
-- | occur
-- | Intresting tidbit: L2 (Euclidean) distance did not solve the challenge, but L1 distance did
getNonenglishness :: (Floating r) => String -> r
getNonenglishness str = sum (zipWith (\x y -> abs (x-y)) (getAlphaFrequencies str) englishAlphaFrequencies)
     + 0.5 * fromIntegral (length (filter (not . (`elem` englishCharacters)) str) )

-- | (Hopefully) Decrypts an English message encrypted with a single-byte XOR
-- | Method: Performs a single-byte XOR on the ciphertext bytestring with every possible byte,
-- | and returns the "least non-English" plaintext result
-- |
-- | Issue: If we XOR the correct key with 32, we get another key that gives us
-- | readable English text (with letter cases switched). Thus there are always at 
-- | least two possible keys. I don't think there's a way to distinguish them in general.
decryptEnglishSingleByteXor :: B.ByteString -> String
decryptEnglishSingleByteXor str 
    = minWith getNonenglishness $ map (BC.unpack . flip singleByteXor str) [0..255]

findEnglishSingleByteXorKey :: B.ByteString -> Word8
findEnglishSingleByteXorKey bStr = 
    minWith (getNonenglishness . BC.unpack . flip singleByteXor bStr) [0..255]

--- Challenge 4: Detect single-byte XOR ---

-- | Reads the lines from the list of ciphertexts given in Challenge Four into a list
getChallengeFourLines :: IO [BC.ByteString]
getChallengeFourLines = (fmap BC.pack) . lines <$> readFile "res/4.txt"

-- | Finds the least non-English plaintext out of a list of single-byte XOR ciphertexts
findEnglishText :: [B.ByteString] -> String
findEnglishText = minWith getNonenglishness . fmap (fromHexWith decryptEnglishSingleByteXor)


--- Challenge 5: Implement repeating-key XOR ---

-- | Encrypts a bytestring with repeating-key xor
repeatingKeyXor :: B.ByteString -> B.ByteString -> B.ByteString
repeatingKeyXor key bstr = B.pack $ BL.zipWith xor (BL.fromStrict bstr) (BL.cycle . BL.fromStrict $ key)


--- Challenge 6: Break repeating-key XOR ---

-- | Computes the hamming/edit distance between two bytes, i.e. the number of differing bits
hammingDistanceByte :: Word8 -> Word8 -> Int
hammingDistanceByte byte1 byte2 = popCount (byte1 `xor` byte2)

-- | Computes the hamming/edit distance between two bytestrings, i.e. the number of differing bits
hammingDistance :: B.ByteString -> B.ByteString -> Int
hammingDistance bstr1 bstr2 = sum $ B.zipWith (hammingDistanceByte) bstr1 bstr2

-- | Splits a bytestring into a list of length-blockSize bytestrings
splitBlocks :: Int -> B.ByteString -> [B.ByteString]
splitBlocks blockSize = takeWhile (not . B.null) . map (B.take blockSize) . (iterate (B.drop blockSize))

-- | Splits a bytestring into numBlocks blocks of length keySize.
--   Computes the normalized edit distance between the first block and each of 
--   the following blocks, and averages them together.
normalizedBlockEditDistance :: (Fractional r) => Int -> Int -> B.ByteString -> r
normalizedBlockEditDistance keySize numBlocks bstr = mean normalizedEditDistances
    where 
        allBlocks :: [B.ByteString]
        allBlocks = splitBlocks keySize bstr

        blocks :: [B.ByteString]
        blocks = take numBlocks allBlocks

        headBlock :: B.ByteString
        headBlock = head blocks

        tailBlocks :: [B.ByteString]
        tailBlocks = tail blocks

        normalizedEditDistances :: (Fractional r0) => [r0]
        normalizedEditDistances = map ((/ (fromIntegral keySize)) . fromIntegral . hammingDistance headBlock) tailBlocks

        mean :: (Fractional r0) => [r0] -> r0
        mean list = (sum list) / (genericLength list)

-- | Reads the encrypted text given in Challenge 6 (res/6.txt) and decodes it into
--   a bytstring
getChallengeSixText :: IO BC.ByteString
getChallengeSixText = fromB64With id . BC.filter (/='\n') <$> BC.readFile "res/6.txt"

-- | Finds the block (key) size which yields the smallest mean normalized edit distance between
--   the first numBlocks blocks in the given bytestring
--   Note: For the range [2..40], this did not return the correct key size for the Challenge 6
--   text for numBlocks < 9.
findVigenereKeySize :: Int -> [Int] -> B.ByteString -> Int
findVigenereKeySize numBlocks range bStr = minWith 
    (\ks -> normalizedBlockEditDistance ks numBlocks bStr) range

challengeSixRange :: (Integral i) => [i]
challengeSixRange = [2..40]

challengeSixNumBlocks :: (Integral i) => i
challengeSixNumBlocks = 9

-- | Finds the key for a repeating-key XOR English ciphertext given the key size
findVigenereKey :: Int -> B.ByteString -> B.ByteString
findVigenereKey keySize bStr  = key
    where
        bStrBlocks = splitBlocks keySize bStr
        bStrT = fmap B.pack . transpose . fmap B.unpack $ bStrBlocks
        keyBytes = fmap (\j -> findEnglishSingleByteXorKey (bStrT !! j)) [0..(keySize-1)]
        key = B.pack keyBytes














