module Set1 
  ( hexToBase64
  )
where

import qualified Data.ByteString as B
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base64 as B64

hexToBase64 :: B.ByteString -> B.ByteString
hexToBase64 = B64.encode . fst . B16.decode
