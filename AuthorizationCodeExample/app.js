//Example using spotify api

class AuthApp{
    constructor(clientId, clientSecret, loginUrl, logoutUrl, redirectUri, authUrl, tokenUrl, scopes){
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.loginUrl = loginUrl;
        this.logoutUrl = logoutUrl;
        this.redirectUri = redirectUri;
        this.authUrl = authUrl;
        this.tokenUrl = tokenUrl;
        this.scopes = scopes;
        this.app = require('express')();
        this.querystring = require('querystring');

        this.cookieStateKey = 'Auth_State';

        this.Login = this.Login.bind(this);
        this.Logout = this.Logout.bind(this);
        this.Callback = this.Callback.bind(this);
        this.CheckTokenExpiration = this.CheckTokenExpiration.bind(this);

        this.app.use(require('cookie-parser')()).use(require('express-session')({secret: 'secret'}));

        //User requests login
        this.app.get(this.loginUrl, this.Login);

        //User requests logout
        this.app.get(this.logoutUrl, this.Logout);

        //oAuth callback
        this.app.get((new URL(this.redirectUri)).pathname, this.Callback);

        //Check token expiration and refresh it if it is expired
        this.app.use(this.CheckTokenExpiration);
    }

    
    use(callback){
        this.app.use(callback);
    }

    get(url, callback){
        if(!callback) return this.app.get(name);
        else this.app.get(url, callback);
    }

    listen(port, callback){
        this.app.listen(port, callback);
    }

    set(key, value){
        this.app.set(key, value);
    }

    on(event, callback){
        this.app.on(event, callback);
    }

    all(path, callback){
        this.app.all(path, callback);
    }

    delete(path, callback){
        this.app.delete(path, callback);
    }

    disable(name){
        this.app.disable(name);
    }

    enable(name){
        this.app.enable(name);
    }

    disabled(name){
        return this.app.disabled(name);
    }

    enabled(name){
        return this.app.enabled(name);
    }

    engine(ext, callback){
        this.app.engine(ext, callback);
    }

    //User requests login
    Login(req, res){
        //State varible
        let state = 'ABCDEFGHIKJLORJO';
        //Store state for comparison later
        res.cookie(this.cookieStateKey, state);
        //Redirect to auth url
        res.redirect(this.authUrl + '?' + this.querystring.stringify({ response_type: 'code', client_id: this.clientId, scope: this.scopes, redirect_uri: this.redirectUri, state: state }));
    }

    //User requests logout
    Logout(req, res){
        //Destroy the session
        req.session.destroy((_) => res.redirect('/'));
    }

    //oAuth callback
    async Callback(req, res){
        let code = req.query.code || null;
        let state = req.query.state || null;
        let storedState = req.cookies ? req.cookies[this.cookieStateKey] : null;
    
        //Compare stored state with state returned by the oAuth API
        if(state === null || state !== storedState) res.redirect('/#' + this.querystring.stringify({ error: 'state_missmatch'}));
        else {
            //Reset cookie
            res.clearCookie(this.cookieStateKey);
    
            //Create options for request
            let authOptions = HelperClass.GenerateTokenRequestOptions(this.tokenUrl, code, this.redirectUri, this.clientId, this.clientSecret);
        
            try{
                //Request accesstoken and refreshtoken token uri
                let body = await HelperClass.MakePostRequest(authOptions);

                //Store accesstoken, refreshtoken and token-expiration date in session
                let tokenExpiration = new Date(Date.now());
                tokenExpiration.setSeconds(tokenExpiration.getSeconds() + body.expires_in);
                req.session.accesstoken = body.access_token;
                req.session.refreshtoken = body.refresh_token;
                req.session.tokenexpiration = tokenExpiration;

                //Redirect back to page
                res.redirect(req.session.callback || '/');
            } catch(err){
                console.error(err);
                res.redirect('/#' + this.querystring.stringify({ error: err }));
            }
        }
    }

    //Check token expiration and refresh it if it is expired
    async CheckTokenExpiration(req, res, next){
        if(req.session.accesstoken){
            if(req.session.tokenexpiration < new Date(Date.now())){
                //Get refreshtoken from session
                let refresh_token = req.session.refreshtoken;

                //Create options for request
                let authOptions = HelperClass.GenerateTokenRefreshOptions(this.tokenUrl, refresh_token, this.clientId, this.clientSecret);

                try{
                    //Request new access token from token uri
                    let body = await HelperClass.MakePostRequest(authOptions);

                    //Store new access token in session
                    req.session.accesstoken = body.access_token;
                } catch(err){
                    console.error(err);
                    res.redirect('/#' + this.querystring.stringify({ error: err }));
                }
            } else next();
        } else next();
    }

    static Create(obj){
        return new AuthApp(obj.ClientId, obj.ClientSecret, obj.LoginUrl, obj.LogoutUrl, obj.RedirectUri, obj.AuthUrl, obj.TokenUrl, obj.Scopes);
    }
}

class HelperClass{
    static request = require('request');

    static GenerateTokenRequestOptions(tokenUrl, code, redirectUri, clientId, clientSecret){
        return {
            url: tokenUrl,
            form:{
                code: code,
                redirect_uri: redirectUri,
                grant_type: 'authorization_code'
            },
            headers: { 'Authorization': 'Basic ' + (new Buffer(clientId + ':' + clientSecret).toString('base64')) },
            json: true
        };
    }

    static GenerateTokenRefreshOptions(tokenUrl, refreshToken, clientId, clientSecret){
        return {
            url: tokenUrl,
            headers: { 'Authorization': 'Basic ' + (new Buffer(clientId + ':' + clientSecret).toString('base64')) },
            form:{
                grant_type: 'refresh_token',
                refresh_token: refreshToken
            },
            json: true
        };
    }

    static async MakePostRequest(options){
        return new Promise((resolve, reject)=>{
            HelperClass.request.post(options, (err, response, body)=>{
                if(err || response.statusCode !== 200) reject(err || response.statusCode);
                else resolve(body);
            });
        });
    }

    static async MakeGetRequest(options){
        return new Promise((resolve, reject)=>{
            HelperClass.request.get(options, (err, response, body)=>{
                if(err || response.statusCode !== 200) reject(err || response.statusCode);
                else resolve(body);
            });
        });
    }
}

const app = AuthApp.Create({
    ClientId: 'your client id',
    ClientSecret: 'your client secret',
    LoginUrl: '/login',
    LogoutUrl: '/logout',
    RedirectUri: 'http://localhost:8888/callback',
    AuthUrl: 'https://accounts.spotify.com/authorize',
    TokenUrl: 'https://accounts.spotify.com/api/token',
    Scopes: 'user-read-private user-read-email'
});

app.set('view engine', 'ejs');

//Index 
app.get('/', async (req, res)=>{
    let user = null;
    if(req.session.accesstoken){
        let options = {
            url: 'https://api.spotify.com/v1/me',
            headers: { 'Authorization': 'Bearer ' + req.session.accesstoken },
            json: true
        };
        
        try{
            user = await HelperClass.MakeGetRequest(options);
        } catch(err){
            res.redirect('/#' + querystring.stringify({ error: err }));
        }
    } 

    res.render('pages/index', { user: user });
});

//Check authenticated
app.use((req, res, next)=>{
    if(!req.session.accesstoken) res.render('pages/error', { error: 'Unauthorized. Please login'});
    else next();
});

app.get('/me', async (req, res)=>{
    let options = {
        url: 'https://api.spotify.com/v1/me', 
        headers: { 'Authorization': 'Bearer ' + req.session.accesstoken },
        json: true
    };

    try{
        let body = await HelperClass.MakeGetRequest(options);
        res.render('pages/user', body)
    } catch(err){
        res.redirect('/#' + querystring.stringify({ error: err }));
    }
});

app.listen(8888);
