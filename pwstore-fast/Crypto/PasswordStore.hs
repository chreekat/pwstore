{-# LANGUAGE OverloadedStrings, BangPatterns, FlexibleInstances #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ViewPatterns #-}
-- |
-- Module      : Crypto.PasswordStore
-- Copyright   : (c) Peter Scott, 2011
-- License     : BSD-style
--
-- Maintainer  : pjscott@iastate.edu
-- Stability   : experimental
-- Portability : portable
--
-- Securely store hashed, salted passwords. If you need to store and verify
-- passwords, there are many wrong ways to do it, most of them all too
-- common. Some people store users' passwords in plain text. Then, when an
-- attacker manages to get their hands on this file, they have the passwords for
-- every user's account. One step up, but still wrong, is to simply hash all
-- passwords with SHA1 or something. This is vulnerable to rainbow table and
-- dictionary attacks. One step up from that is to hash the password along with
-- a unique salt value. This is vulnerable to dictionary attacks, since guessing
-- a password is very fast. The right thing to do is to use a slow hash
-- function, to add some small but significant delay, that will be negligible
-- for legitimate users but prohibitively expensive for someone trying to guess
-- passwords by brute force. That is what this library does. It iterates a
-- SHA256 hash, with a random salt, a few thousand times. This scheme is known
-- as PBKDF1, and is generally considered secure; there is nothing innovative
-- happening here.
--
-- The API here is very simple. What you store are called /password hashes/.
-- They are strings (technically, ByteStrings) that look like this:
--
-- > "sha256|17|Ge9pg8a/r4JW356Uux2JHg==|Fdv4jchzDlRAs6WFNUarxLngaittknbaHFFc0k8hAy0="
--
-- Each password hash shows the algorithm, the strength (more on that later),
-- the salt, and the hashed-and-salted password. You store these on your server,
-- in a database, for when you need to verify a password. You make a password
-- hash with the 'makePassword' function. Here's an example:
--
-- > >>> makePassword "hunter2" 17
-- > "sha256|12|lMzlNz0XK9eiPIYPY96QCQ==|1ZJ/R3qLEF0oCBVNtvNKLwZLpXPM7bLEy/Nc6QBxWro="
--
-- This will hash the password @\"hunter2\"@, with strength 17, which is a good
-- default value. The strength here determines how long the hashing will
-- take. When doing the hashing, we iterate the SHA256 hash function
-- @2^strength@ times, so increasing the strength by 1 makes the hashing take
-- twice as long. When computers get faster, you can bump up the strength a
-- little bit to compensate. You can strengthen existing password hashes with
-- the 'strengthenPassword' function. Note that 'makePassword' needs to generate
-- random numbers, so its return type is 'IO' 'ByteString'. If you want to avoid
-- the 'IO' monad, you can generate your own salt and pass it to
-- 'makePasswordSalt'.
--
-- Your strength value should not be less than 16, and 17 is a good default
-- value at the time of this writing, in 2014.  OWASP suggests adding 1 to the
-- strength every two years.
--
-- Once you've got your password hashes, the second big thing you need to do
-- with them is verify passwords against them. When a user gives you a password,
-- you compare it with a password hash using the 'verifyPassword' function:
--
-- > >>> verifyPassword "wrong guess" passwordHash
-- > False
-- > >>> verifyPassword "hunter2" passwordHash
-- > True
--
-- These two functions are really all you need. If you want to make existing
-- password hashes stronger, you can use 'strengthenPassword'. Just pass it an
-- existing password hash and a new strength value, and it will return a new
-- password hash with that strength value, which will match the same password as
-- the old password hash.
--
-- Note that, as of version 2.4, you can also use PBKDF2, and specify the exact
-- iteration count. This does not have a significant effect on security, but can
-- be handy for compatibility with other code.

module Crypto.PasswordStore (

        -- * Algorithms
        pbkdf1,                 -- :: ByteString -> Salt -> Int -> ByteString
        pbkdf2,                 -- :: ByteString -> Salt -> Int -> ByteString

        -- * Registering and verifying passwords
        makePassword,           -- :: ByteString -> Int -> IO ByteString
        makePasswordWith,       -- :: (ByteString -> Salt -> Int -> ByteString) ->
                                --    ByteString -> Int -> IO ByteString
        makePasswordSalt,       -- :: ByteString -> ByteString -> Int -> ByteString
        makePasswordSaltWith,   -- :: (ByteString -> Salt -> Int -> ByteString) ->
                                --    ByteString -> Salt -> Int -> ByteString
        verifyPassword,         -- :: ByteString -> ByteString -> Bool
        verifyPasswordWith,     -- :: (ByteString -> Salt -> Int -> ByteString) ->
                                --    (Int -> Int) -> ByteString -> ByteString -> Bool

        -- * Updating password hash strength
        strengthenPassword,     -- :: ByteString -> Int -> ByteString
        passwordStrength,       -- :: ByteString -> Int

        -- * Utilities
        Salt,
        isPasswordFormatValid,  -- :: ByteString -> Bool
        genSaltIO,              -- :: IO Salt
        genSaltRandom,          -- :: (RandomGen b) => b -> (Salt, b)
        makeSalt,               -- :: ByteString -> Salt
        exportSalt,             -- :: Salt -> ByteString
        importSalt              -- :: ByteString -> Salt
  ) where


import qualified Crypto.Hash as CH
import qualified Crypto.Hash.SHA256 as H
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.Binary as Binary
import Control.Monad
import Control.Monad.ST
import Data.Byteable (toBytes)
import Data.STRef
import Data.Bits
import Data.ByteString.Char8 (ByteString)

import "pwstore-purehaskell" Crypto.PasswordStore as Pure
    hiding (pbkdf1, makePassword, makePasswordSalt, verifyPassword)

-- | Hash a password with a given strength (17 is a good default). The output of
-- this function can be written directly to a password file or
-- database. Generates a salt using high-quality randomness from
-- @\/dev\/urandom@ or (if that is not available, for example on Windows)
-- 'System.Random', which is included in the hashed output.
makePassword :: ByteString -> Int -> IO ByteString
makePassword = makePasswordWith pbkdf1

-- | Hash a password with a given strength (17 is a good default), using a given
-- salt. The output of this function can be written directly to a password file
-- or database. Example:
--
-- > >>> makePasswordSalt "hunter2" (makeSalt "72cd18b5ebfe6e96") 17
-- > "sha256|17|NzJjZDE4YjVlYmZlNmU5Ng==|i5VbJNJ3I6SPnxdK5pL0dHw4FoqnHYpSUXp70coXjOI="
makePasswordSalt :: ByteString -> Salt -> Int -> ByteString
makePasswordSalt = makePasswordSaltWith pbkdf1 (2^)

-- | Like 'verifyPasswordWith', but uses 'pbkdf1' as algorithm.
verifyPassword :: ByteString -> ByteString -> Bool
verifyPassword = verifyPasswordWith pbkdf1 (2^)

---------------------
-- Cryptographic base
---------------------

-- | PBKDF1 key-derivation function. Takes a password, a 'Salt', and a number of
-- iterations. The number of iterations should be at least 1000, and probably
-- more. 5000 is a reasonable number, computing almost instantaneously. This
-- will give a 32-byte 'ByteString' as output. Both the salt and this 32-byte
-- key should be stored in the password file. When a user wishes to authenticate
-- a password, just pass it and the salt to this function, and see if the output
-- matches.
pbkdf1 :: ByteString -> Salt -> Int -> ByteString
pbkdf1 password (exportSalt -> salt) iter = hashRounds first_hash (iter + 1)
    where first_hash = H.finalize $ H.init `H.update` password `H.update` salt

-- | Hash a 'ByteString' for a given number of rounds. The number of rounds is 0
-- or more. If the number of rounds specified is 0, the ByteString will be
-- returned unmodified.
hashRounds :: ByteString -> Int -> ByteString
hashRounds (!bs) 0 = bs
hashRounds bs rounds = hashRounds (H.hash bs) (rounds - 1)

-- | Computes the hmacSHA256 of the given message, with the given 'Salt'.
hmacSHA256 :: ByteString
           -- ^ The secret (the salt)
           -> ByteString
           -- ^ The clear-text message
           -> ByteString
           -- ^ The encoded message
hmacSHA256 secret msg =
    toBytes (CH.hmacGetDigest (CH.hmac secret msg) :: CH.Digest CH.SHA256)

-- | PBKDF2 key-derivation function.
-- For details see @http://tools.ietf.org/html/rfc2898@.
-- @32@ is the most common digest size for @SHA256@, and is
-- what the algorithm internally uses.
-- @HMAC+SHA256@ is used as @PRF@, because @HMAC+SHA1@ is considered too weak.
pbkdf2 :: ByteString -> Salt -> Int -> ByteString
pbkdf2 password (exportSalt -> salt) c =
    let hLen = 32
        dkLen = hLen in go hLen dkLen
  where
    go hLen dkLen | dkLen > (2^(32 :: Int) - 1) * hLen = error "Derived key too long."
                  | otherwise =
                      let !l = ceiling ((fromIntegral dkLen / fromIntegral hLen) :: Double)
                          !r = dkLen - (l - 1) * hLen
                          chunks = [f i | i <- [1 .. l]]
                      in (B.concat . init $ chunks) `B.append` B.take r (last chunks)

    -- The @f@ function, as defined in the spec.
    -- It calls 'u' under the hood.
    f :: Int -> ByteString
    f i = let !u1 = hmacSHA256 password (salt `B.append` int i)
      -- Using the ST Monad, for maximum performance.
      in runST $ do
          u <- newSTRef u1
          accum <- newSTRef u1
          forM_ [2 .. c] $ \_ -> do
            modifySTRef' u (hmacSHA256 password)
            currentU <- readSTRef u
            modifySTRef' accum (`xor'` currentU)
          readSTRef accum

    -- int(i), as defined in the spec.
    int :: Int -> ByteString
    int i = let str = BL.unpack . Binary.encode $ i
            in BS.pack $ drop (length str - 4) str

    -- | A convenience function to XOR two 'ByteString' together.
    xor' :: ByteString -> ByteString -> ByteString
    xor' !b1 !b2 = BS.pack $ BS.zipWith xor b1 b2

#if !MIN_VERSION_base(4, 6, 0)
-- | Strict version of 'modifySTRef'
modifySTRef' :: STRef s a -> (a -> a) -> ST s ()
modifySTRef' ref f = do
    x <- readSTRef ref
    let x' = f x
    x' `seq` writeSTRef ref x'
#endif
