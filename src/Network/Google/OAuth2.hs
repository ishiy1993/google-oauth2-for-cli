{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.Google.OAuth2
    ( getToken
    , OAuth2Client(..)
    , Scope
    , AccessToken
    ) where

import Control.Concurrent
import Control.Exception (onException, throwIO, catch, IOException)
import Control.Monad (join)
import Data.Aeson
import qualified Data.ByteString.Char8 as B
import Data.Monoid ((<>))
import Data.String (fromString)
import Data.Time
import Network.HTTP.Types (renderSimpleQuery, status200)
import Network.HTTP.Req
import Network.Wai
import Network.Wai.Handler.Warp
import System.Directory
import System.Exit
import System.FilePath
import System.IO (hPutStrLn, stderr)
import System.Posix.Files

getToken :: OAuth2Client -> FilePath -> [Scope] -> IO AccessToken
getToken c tokenFile scopes = readToken c tokenFile `catch` download
    where
        download :: IOException -> IO AccessToken
        download = const $ downloadToken c tokenFile scopes

readToken :: OAuth2Client -> FilePath -> IO AccessToken
readToken c tokenFile = do
    t <- read <$> readFile tokenFile
    let dt = 5
        -- Avoid latent error
        e = fromIntegral $ expiresIn t - dt
    now <- getCurrentTime
    mt <- getModificationTime tokenFile
    if now < addUTCTime e mt
       then return $ B.pack $ accessToken t
       else do
           t' <- getNewTokenInfo c (refreshToken t)
           saveTokenInfo tokenFile t'
           return $ B.pack $ accessToken t'

getNewTokenInfo :: OAuth2Client -> RefreshToken -> IO TokenInfo
getNewTokenInfo c rt = do
    let body = ReqBodyUrlEnc $
                   "refresh_token" =: rt <>
                   "client_id" =: clientId c <>
                   "client_secret" =: clientSecret c <>
                   "grant_type" =: ("refresh_token" :: String)
    res <- req POST tokenUrl body jsonResponse mempty
    let t' = responseBody res
    return $ t' { refreshToken = rt }

saveTokenInfo :: FilePath -> TokenInfo -> IO ()
saveTokenInfo tokenFile t = do
    createDirectoryIfMissing True $ takeDirectory tokenFile
    writeFile tokenFile (show t)
    let fm = unionFileModes ownerReadMode ownerWriteMode
    setFileMode tokenFile fm

downloadToken :: OAuth2Client -> FilePath -> [Scope] -> IO AccessToken
downloadToken c tokenFile scopes = do
    code <- getCode c scopes
    t <- exchangeCode c code
    saveTokenInfo tokenFile t
    return $ B.pack $ accessToken t

getCode :: OAuth2Client -> [Scope] -> IO Code
getCode c scopes = do
    m <- newEmptyMVar
    let st = setHost (fromString localhost)
             $ setPort serverPort defaultSettings
    _ <- forkIO $ runSettings st (server m)
            `onException` do
                hPutStrLn stderr $ "Unable to use port " ++ show serverPort
                putMVar m Nothing
    let authUri = "https://accounts.google.com/o/oauth2/v2/auth"
        q = renderSimpleQuery True
                [ ("scope", B.pack $ unwords scopes)
                , ("redirect_uri", B.pack redirectUri)
                , ("response_type", "code")
                , ("client_id", B.pack $ clientId c)
                ]
    putStrLn "Open the following uri in your browser:"
    putStrLn $ B.unpack $ authUri <> q
    mc <- takeMVar m
    case mc of
         Nothing -> die "Unable to get code"
         Just code -> return code

server :: MVar (Maybe Code) -> Application
server m request respond = do
    putMVar m $ B.unpack <$> join (lookup "code" $ queryString request)
    respond $ responseLBS status200
                          [("Content-Type", "text/plain")]
                          "Return your app"

exchangeCode :: OAuth2Client -> Code -> IO TokenInfo
exchangeCode c code = do
    let body = ReqBodyUrlEnc $
                   "code" =: code <>
                   "client_id" =: clientId c <>
                   "client_secret" =: clientSecret c <>
                   "redirect_uri" =: redirectUri <>
                   "grant_type" =: ("authorization_code" :: String)
    res <- req POST tokenUrl body jsonResponse mempty
    return $ responseBody res

tokenUrl :: Url 'Https
tokenUrl = https "accounts.google.com" /: "o" /: "oauth2" /: "token"

serverPort :: Port
serverPort = 8017

localhost :: String
localhost = "127.0.0.1"

redirectUri :: String
redirectUri = concat ["http://", localhost, ":", show serverPort]

data OAuth2Client = OAuth2Client
    { clientId :: String
    , clientSecret :: String
    } deriving (Show, Read)

type AccessToken = B.ByteString
type RefreshToken = String
type Code = String

type Scope = String

data TokenInfo = TokenInfo
    { accessToken :: String
    , refreshToken :: String
    , expiresIn :: Int
    } deriving (Show, Read)

instance FromJSON TokenInfo where
    parseJSON (Object v) = TokenInfo <$> v .: "access_token"
                                     <*> v .:? "refresh_token" .!= ""
                                     <*> v .: "expires_in"
    parseJSON _ = mempty

instance MonadHttp IO where
  handleHttpException = throwIO
