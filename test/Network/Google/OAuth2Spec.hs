{-# LANGUAGE OverloadedStrings #-}
module Network.Google.OAuth2Spec where

import Test.Hspec
import Network.Google.OAuth2

spec :: Spec
spec =
    describe "getToken" $
        it "returns the access token" $ do
            let tokenFile = "token.info"
                token = "TokenInfo {accessToken = \"access_token\", refreshToken = \"refresh_token\", expiresIn = 3600}"
                c = OAuth2Client "client_id" "client_secret"
            writeFile tokenFile token
            getToken c tokenFile [] `shouldReturn` "access_token"

