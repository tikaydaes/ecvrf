-- | RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite byte 0x03) in pure Haskell.
module Crypto.ECVRF
  ( suiteByte
  , secretKeyLen
  , publicKeyLen
  , proofLen
  , betaLen
  , isPublicKey
  , derivePublicKey
  , prove
  , verify
  , proofToHash
  ) where

import Data.Bits (shiftL, shiftR, testBit, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)
import qualified Crypto.Hash.SHA512 as SHA512

suiteByte :: Word8
suiteByte = 0x03

secretKeyLen, publicKeyLen, proofLen, betaLen, challengeLen :: Int
secretKeyLen = 32
publicKeyLen = 32
proofLen = 80
betaLen = 64
challengeLen = 16

-- Edwards25519 parameters
fieldP :: Integer
fieldP = shiftL 1 255 - 19

groupQ :: Integer
groupQ = shiftL 1 252 + 27742317777372353535851937790883648493

modP :: Integer -> Integer
modP x = x `mod` fieldP

modQ :: Integer -> Integer
modQ x = x `mod` groupQ

modPow :: Integer -> Integer -> Integer -> Integer
modPow base0 exp0 m = go (base0 `mod` m) exp0 1
  where
    go _ 0 acc = acc
    go b e acc =
      let acc' = if testBit e 0 then (acc * b) `mod` m else acc
      in go ((b * b) `mod` m) (shiftR e 1) acc'

invP :: Integer -> Integer
invP a = modPow a (fieldP - 2) fieldP

curveD :: Integer
curveD = modP ((-121665) * invP 121666)

sqrtM1 :: Integer
sqrtM1 = modPow 2 (shiftR (fieldP - 1) 2) fieldP

xRecover :: Integer -> Maybe Integer
xRecover y =
  let yy = modP (y * y)
      u = modP (yy - 1)
      v = modP (curveD * yy + 1)
      xx = modP (u * invP v)
      x0 = modPow xx (shiftR (fieldP + 3) 3) fieldP
      x1 = if modP (x0 * x0 - xx) /= 0 then modP (x0 * sqrtM1) else x0
  in if modP (x1 * x1 - xx) /= 0
     then Nothing
     else Just (if testBit x1 0 then fieldP - x1 else x1)

-- Extended homogeneous coordinates (X, Y, Z, T)
data Point = Point !Integer !Integer !Integer !Integer

identityPoint :: Point
identityPoint = Point 0 1 1 0

basePoint :: Point
basePoint =
  let by = modP (4 * invP 5)
  in case xRecover by of
       Just bx -> Point bx by 1 (modP (bx * by))
       Nothing -> error "failed to initialize Edwards25519 base point"

pointAdd :: Point -> Point -> Point
pointAdd (Point x1 y1 z1 t1) (Point x2 y2 z2 t2) =
  let a = modP ((y1 - x1) * (y2 - x2))
      b = modP ((y1 + x1) * (y2 + x2))
      c = modP (2 * t1 * t2 * curveD)
      dd = modP (2 * z1 * z2)
      e = modP (b - a)
      f = modP (dd - c)
      g = modP (dd + c)
      h = modP (b + a)
  in Point (modP (e * f)) (modP (g * h)) (modP (f * g)) (modP (e * h))

pointMulBy8 :: Point -> Point
pointMulBy8 pt =
  let p2 = pointAdd pt pt
      p4 = pointAdd p2 p2
  in pointAdd p4 p4

pointMulRaw :: Point -> Integer -> Point
pointMulRaw pt k0 = go identityPoint pt k0
  where
    go acc _ 0 = acc
    go acc addend k =
      let acc' = if testBit k 0 then pointAdd acc addend else acc
      in go acc' (pointAdd addend addend) (shiftR k 1)

pointMul :: Point -> Integer -> Point
pointMul pt k = pointMulRaw pt (modQ k)

isIdentity :: Point -> Bool
isIdentity (Point x y z _) = modP x == 0 && modP (y - z) == 0

os2ipLE :: ByteString -> Integer
os2ipLE = BS.foldr (\b acc -> shiftL acc 8 .|. fromIntegral b) 0

i2ospLE :: Integer -> Int -> ByteString
i2ospLE n len = BS.pack [fromIntegral (shiftR n (8 * i) .&. 0xff) | i <- [0 .. len - 1]]

pointToBytes :: Point -> ByteString
pointToBytes (Point x y z _) =
  let zi = invP z
      ax = modP (x * zi)
      ay = modP (y * zi)
      bs = i2ospLE ay 32
      lastByte = BS.index bs 31 .|. (if testBit ax 0 then 0x80 else 0x00)
  in BS.take 31 bs <> BS.singleton lastByte

bytesToPoint :: ByteString -> Maybe Point
bytesToPoint bs
  | BS.length bs /= 32 = Nothing
  | otherwise =
      let b31 = BS.index bs 31
          signBit = testBit b31 7
          yBytes = BS.take 31 bs <> BS.singleton (b31 .&. 0x7f)
          y = os2ipLE yBytes
      in if y >= fieldP
         then Nothing
         else case xRecover y of
                Nothing -> Nothing
                Just x0 ->
                  if x0 == 0 && signBit
                  then Nothing
                  else let x = if testBit x0 0 /= signBit then fieldP - x0 else x0
                       in Just (Point x y 1 (modP (x * y)))

validateKey :: ByteString -> Maybe Point
validateKey pk = do
  y <- bytesToPoint pk
  if isIdentity (pointMulBy8 y) then Nothing else Just y

isPublicKey :: ByteString -> Bool
isPublicKey pk = case validateKey pk of
  Just _ -> True
  Nothing -> False

expandSecretKey :: ByteString -> Maybe (Integer, ByteString)
expandSecretKey sk
  | BS.length sk /= secretKeyLen = Nothing
  | otherwise =
      let h = SHA512.hash sk
          xb0 = BS.take 32 h
          b0 = BS.index xb0 0 .&. 248
          b31 = (BS.index xb0 31 .&. 127) .|. 64
          xb = BS.singleton b0 <> BS.take 30 (BS.drop 1 xb0) <> BS.singleton b31
      in Just (os2ipLE xb, BS.drop 32 h)

encodeToCurveTAI :: ByteString -> ByteString -> Maybe Point
encodeToCurveTAI pk alpha = go (0 :: Int)
  where
    prefix = BS.pack [suiteByte, 0x01] <> pk <> alpha
    go ctr
      | ctr > 255 = Nothing
      | otherwise =
          let h = SHA512.hash (prefix <> BS.pack [fromIntegral ctr, 0x00])
          in case bytesToPoint (BS.take 32 h) of
               Just pt -> Just (pointMulBy8 pt)
               Nothing -> go (ctr + 1)

challengeGeneration :: Point -> Point -> Point -> Point -> Point -> (Integer, ByteString)
challengeGeneration y h gamma u v =
  let hashIn = BS.pack [suiteByte, 0x02]
            <> pointToBytes y
            <> pointToBytes h
            <> pointToBytes gamma
            <> pointToBytes u
            <> pointToBytes v
            <> BS.singleton 0x00
      cBytes = BS.take challengeLen (SHA512.hash hashIn)
  in (os2ipLE cBytes, cBytes)

gammaToHash :: Point -> ByteString
gammaToHash gamma =
  SHA512.hash (BS.pack [suiteByte, 0x03] <> pointToBytes (pointMulBy8 gamma) <> BS.singleton 0x00)

decodeProof :: ByteString -> Maybe (Point, Integer, ByteString, Integer)
decodeProof pi_
  | BS.length pi_ /= proofLen = Nothing
  | otherwise = do
      gamma <- bytesToPoint (BS.take 32 pi_)
      let cBytes = BS.take challengeLen (BS.drop 32 pi_)
          c = os2ipLE cBytes
          s = os2ipLE (BS.drop 48 pi_)
      if s >= groupQ then Nothing else Just (gamma, c, cBytes, s)

derivePublicKey :: ByteString -> Maybe ByteString
derivePublicKey sk = do
  (x, _) <- expandSecretKey sk
  return (pointToBytes (pointMulRaw basePoint x))

prove :: ByteString -> ByteString -> Maybe ByteString
prove sk alpha = do
  (x, prefix) <- expandSecretKey sk
  let y = pointMulRaw basePoint x
      pk = pointToBytes y
  h <- encodeToCurveTAI pk alpha
  let gamma = pointMulRaw h x
      k = modQ (os2ipLE (SHA512.hash (prefix <> pointToBytes h)))
      u = pointMul basePoint k
      v = pointMul h k
      (c, cBytes) = challengeGeneration y h gamma u v
      s = modQ (k + c * x)
  return (pointToBytes gamma <> cBytes <> i2ospLE s 32)

verify :: ByteString -> ByteString -> ByteString -> Maybe ByteString
verify pk pi_ alpha = do
  y <- validateKey pk
  (gamma, c, cBytes, s) <- decodeProof pi_
  h <- encodeToCurveTAI pk alpha
  let negC = modQ (groupQ - c)
      u = pointAdd (pointMul basePoint s) (pointMul y negC)
      v = pointAdd (pointMul h s) (pointMul gamma negC)
      (_, cPrimeBytes) = challengeGeneration y h gamma u v
  if cBytes == cPrimeBytes
    then Just (gammaToHash gamma)
    else Nothing

proofToHash :: ByteString -> Maybe ByteString
proofToHash pi_ = do
  (gamma, _, _, _) <- decodeProof pi_
  return (gammaToHash gamma)
