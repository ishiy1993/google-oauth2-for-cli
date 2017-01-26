{-# LANGUAGE OverloadedStrings #-}
module Network.Google.OAuth2 where

import Control.Concurrent
import Control.Exception (throwIO)
import Data.Aeson
import qualified Data.ByteString.Char8 as B
import Data.Monoid ((<>))
import Data.Time
import Network.HTTP.Types (renderSimpleQuery, status200)
import Network.HTTP.Req
import Network.Wai
import Network.Wai.Handler.Warp
import System.Directory
import System.FilePath

getToken :: OAuth2Client -> FilePath -> [Scope] -> IO AccessToken
getToken c tokenFile scopes = do
    b <- doesFileExist tokenFile
    if b then readToken c tokenFile else downloadToken c tokenFile scopes

readToken :: OAuth2Client -> FilePath -> IO AccessToken
readToken c tokenFile = do
    token <- read <$> readFile tokenFile
    let e = fromIntegral $ expiresIn token - 5
    now <- getCurrentTime
    t <- getModificationTime tokenFile
    if now < addUTCTime e t
       then return $ B.pack $ accessToken token
       else getNewToken c tokenFile (refreshToken token)

getNewToken :: OAuth2Client -> FilePath -> RefreshToken -> IO AccessToken
getNewToken c tokenFile rt = do
    let body = ReqBodyUrlEnc $
                   "refresh_token" =: rt <>
                   "client_id" =: clientId c <>
                   "client_secret" =: clientSecret c <>
                   "grant_type" =: ("refresh_token" :: String)
        Just (url, opt) = parseUrlHttps tokenUri
    res <- req POST url body jsonResponse opt
    let t' = responseBody res :: TokenInfo
        t = t' { refreshToken = rt }
    writeFile tokenFile (show t)
    return $ B.pack $ accessToken t

tokenUri = "https://accounts.google.com/o/oauth2/token"

serverPort :: Port
serverPort = 8017

downloadToken :: OAuth2Client -> FilePath -> [Scope] -> IO AccessToken
downloadToken c tokenFile scopes = do
    let authUri = "https://accounts.google.com/o/oauth2/v2/auth"
        redirectUri = "http://127.0.0.1:" ++ show serverPort
        q = renderSimpleQuery True
                [ ("scope", B.pack $ unwords scopes)
                , ("redirect_uri", B.pack redirectUri)
                , ("response_type", "code")
                , ("client_id", B.pack $ clientId c)
                ]
    -- get code
    putStrLn "Open the following uri in your browser:"
    putStrLn $ B.unpack $ authUri <> q
    m <- newEmptyMVar
    _ <- forkIO $ startServer m
    code <- takeMVar m

    -- exchange code
    let Just (url, opt) = parseUrlHttps tokenUri
        body = ReqBodyUrlEnc $
                   "code" =: code <>
                   "client_id" =: clientId c <>
                   "client_secret" =: clientSecret c <>
                   "redirect_uri" =: redirectUri <>
                   "grant_type" =: ("authorization_code" :: String)
    res <- req POST url body jsonResponse opt
    let t = responseBody res :: TokenInfo
    createDirectoryIfMissing True $ takeDirectory tokenFile
    writeFile tokenFile (show t)
    putStrLn $ "Save token in " ++ tokenFile

    return $ B.pack $ accessToken t

startServer :: MVar Code -> IO ()
startServer m = run serverPort (app m)

app :: MVar Code -> Application
app m request respond = do
    print request
    case lookup "code" (queryString request) of
         Just (Just code) -> putMVar m $ B.unpack code
         _ -> return ()
    respond $ responseLBS status200
                          [("Content-Type", "text/plain")]
                          "Return your app"

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
                                     <*> (v .:? "refresh_token" .!= "")
                                     <*> v .: "expires_in"
    parseJSON _ = mempty

instance MonadHttp IO where
  handleHttpException = throwIO
