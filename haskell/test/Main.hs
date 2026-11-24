{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Data.Aeson (FromJSON (..), eitherDecodeFileStrict', withObject, (.:))
import qualified Data.ByteString as BS
import Data.Char (digitToInt, isHexDigit)
import Data.Word (Word8)
import Numeric (showHex)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

import Crypto.ECVRF (derivePublicKey, isPublicKey, proofToHash, prove, verify)

data VectorFile = VectorFile
  { vfSuite :: String
  , vfSpec :: String
  , vfVectors :: [PositiveVector]
  , vfNegativeVectors :: [NegativeVector]
  }

data PositiveVector = PositiveVector
  { pvLabel :: String
  , pvSk :: String
  , pvPk :: String
  , pvAlpha :: String
  , pvPi :: String
  , pvBeta :: String
  }

data NegativeVector = NegativeVector
  { nvDescription :: String
  , nvPk :: String
  , nvAlpha :: String
  , nvPi :: String
  , nvExpectedVerify :: Bool
  }

instance FromJSON VectorFile where
  parseJSON = withObject "VectorFile" $ \o ->
    VectorFile
      <$> o .: "suite"
      <*> o .: "spec"
      <*> o .: "vectors"
      <*> o .: "negative_vectors"

instance FromJSON PositiveVector where
  parseJSON = withObject "PositiveVector" $ \o ->
    PositiveVector
      <$> o .: "label"
      <*> o .: "sk"
      <*> o .: "pk"
      <*> o .: "alpha"
      <*> o .: "pi"
      <*> o .: "beta"

instance FromJSON NegativeVector where
  parseJSON = withObject "NegativeVector" $ \o ->
    NegativeVector
      <$> o .: "description"
      <*> o .: "pk"
      <*> o .: "alpha"
      <*> o .: "pi"
      <*> o .: "expected_verify"

hexDecode :: String -> BS.ByteString
hexDecode s = BS.pack (go s)
  where
    go [] = []
    go (a:b:rest)
      | isHexDigit a && isHexDigit b =
          (fromIntegral (digitToInt a * 16 + digitToInt b) :: Word8) : go rest
      | otherwise = error "invalid hex"
    go _ = error "odd hex length"

hexEncode :: BS.ByteString -> String
hexEncode = concatMap toHex . BS.unpack
  where
    toHex b = let s = showHex b "" in if length s == 1 then '0' : s else s

main :: IO ()
main = do
  eDoc <- eitherDecodeFileStrict' "../vectors/vectors.json"
  doc <- case eDoc of
    Left err -> hPutStrLn stderr ("parse vectors.json: " ++ err) >> exitFailure
    Right d -> return d

  if vfSuite doc /= "ECVRF-EDWARDS25519-SHA512-TAI"
    then hPutStrLn stderr ("unexpected suite: " ++ vfSuite doc) >> exitFailure
    else return ()

  if vfSpec doc /= "RFC 9381"
    then hPutStrLn stderr ("unexpected spec: " ++ vfSpec doc) >> exitFailure
    else return ()

  let posResults = concatMap checkPositive (vfVectors doc)
      negResults = map checkNegative (vfNegativeVectors doc)
      failures = [msg | Left msg <- posResults ++ negResults]
      total = length posResults + length negResults

  mapM_ (hPutStrLn stderr . ("FAIL: " ++)) failures
  putStrLn $ "Haskell tests: " ++ show (total - length failures) ++ " passed, " ++ show (length failures) ++ " failed"
  if null failures then return () else exitFailure

checkPositive :: PositiveVector -> [Either String ()]
checkPositive v =
  let sk = hexDecode (pvSk v)
      alpha = hexDecode (pvAlpha v)
      pk = derivePublicKey sk
      pi_ = prove sk alpha
      betaHash = pi_ >>= proofToHash
      betaVerify = do
        pk' <- pk
        pi' <- pi_
        verify pk' pi' alpha
      expect cond msg = if cond then Right () else Left (pvLabel v ++ ": " ++ msg)
  in [ expect (fmap hexEncode pk == Just (pvPk v)) "pk mismatch"
     , expect (maybe False isPublicKey pk) "isPublicKey false"
     , expect (fmap hexEncode pi_ == Just (pvPi v)) "pi mismatch"
     , expect (fmap hexEncode betaHash == Just (pvBeta v)) "proofToHash mismatch"
     , expect (fmap hexEncode betaVerify == Just (pvBeta v)) "verify mismatch"
     ]

checkNegative :: NegativeVector -> Either String ()
checkNegative v =
  let res = verify (hexDecode (nvPk v)) (hexDecode (nvPi v)) (hexDecode (nvAlpha v))
      valid = case res of
        Just _ -> True
        Nothing -> False
  in if valid == nvExpectedVerify v
     then Right ()
     else Left (nvDescription v ++ ": expected " ++ show (nvExpectedVerify v) ++ ", got " ++ show valid)
