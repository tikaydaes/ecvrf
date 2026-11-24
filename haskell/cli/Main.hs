module Main (main) where

import qualified Data.ByteString as BS
import Data.Char (digitToInt, isHexDigit)
import Data.Word (Word8)
import Numeric (showHex)
import System.Environment (getArgs)
import System.Exit (exitFailure, exitWith, ExitCode(..))
import System.IO (hPutStrLn, stderr)

import Crypto.ECVRF (derivePublicKey, prove, verify)

hexDecode :: String -> Maybe BS.ByteString
hexDecode s
  | odd (length s) = Nothing
  | otherwise = BS.pack <$> go s
  where
    go [] = Just []
    go (a:b:rest)
      | isHexDigit a && isHexDigit b =
          let byte = fromIntegral (digitToInt a * 16 + digitToInt b) :: Word8
          in (byte :) <$> go rest
      | otherwise = Nothing
    go _ = Nothing

hexEncode :: BS.ByteString -> String
hexEncode = concatMap toHex . BS.unpack
  where
    toHex b = let s = showHex b "" in if length s == 1 then '0' : s else s

main :: IO ()
main = do
  args <- getArgs
  case args of
    ["prove", skHex, alphaHex] ->
      case (hexDecode skHex, hexDecode alphaHex) of
        (Just sk, Just alpha) ->
          case prove sk alpha of
            Just pi_ -> putStrLn (hexEncode pi_)
            Nothing -> hPutStrLn stderr "prove failed" >> exitFailure
        _ -> exitWith (ExitFailure 2)
    ["verify", pkHex, piHex, alphaHex] ->
      case (hexDecode pkHex, hexDecode piHex, hexDecode alphaHex) of
        (Just pk, Just pi_, Just alpha) ->
          case verify pk pi_ alpha of
            Just beta -> putStrLn (hexEncode beta)
            Nothing -> exitFailure
        _ -> exitWith (ExitFailure 2)
    ["derive-pk", skHex] ->
      case hexDecode skHex of
        Just sk ->
          case derivePublicKey sk of
            Just pk -> putStrLn (hexEncode pk)
            Nothing -> hPutStrLn stderr "derive-pk failed" >> exitFailure
        Nothing -> exitWith (ExitFailure 2)
    _ -> do
      hPutStrLn stderr "usage: ecvrf-cli prove <sk> <alpha> | verify <pk> <pi> <alpha> | derive-pk <sk>"
      exitWith (ExitFailure 2)
