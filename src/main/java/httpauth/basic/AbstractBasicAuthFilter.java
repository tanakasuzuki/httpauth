package httpauth.basic;

import java.io.IOException;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class AbstractBasicAuthFilter implements Filter {

    /** HTTPのHeader 認証 */
    protected static final String HTTP_HEADER_AUTHORIZATION = "Authorization";

    /** HTTPのHeader WWW-Authenticate */
    protected static final String HTTP_HEADER_WWW_AUTHENTICATE  = "WWW-Authenticate";

    /** 認証タイプ */
    protected static String AUTH_TYPE_BASIC = "Basic";


    /** レルム */
    String realm;

    /** WWW-Authenticateヘッダの値にいれる文字列 Basic realm="realm" */
    String authenticateValue;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.realm = filterConfig.getInitParameter("realm");
        authenticateValue = AUTH_TYPE_BASIC + " realm=\""+realm+"\"";
    }

    /**
     * 認証が必要なことを接続元へ応答を返す
     *
     * @param request クライアントからのリクエスト
     * @param response サーバからのレスポンス
     */
    protected void responseAuthnicate(HttpServletRequest request, HttpServletResponse response){
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader(HTTP_HEADER_WWW_AUTHENTICATE, authenticateValue);
    }

    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain chain) throws IOException, ServletException{
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;
        String authHeader = request.getHeader(HTTP_HEADER_AUTHORIZATION);
        
        
        
        if(authHeader == null){
            // 認証を伴わないリクエストの場合認証が必要であることを返す:
            this.responseAuthnicate(request, response);
            return;
        }
        

        // 認証ヘッダーの値を認証方法とエンコードされたユーザ名:パスワードに分ける:
        String[] authPair = authHeader.split(" ");
        if(authPair.length != 2){
            // 分割できなかった場合は認証失敗
            return;
        }

        String authType = authPair[0];
        if(!AUTH_TYPE_BASIC.equals(authType)){
            // クライアントからBasic認証以外の接続があった場合は認証失敗
            return;
        }

        //エンコードされた認証のデータデコードしてユーザ名とパスワードに分ける
        String decode = new String(Base64.getDecoder().decode(authPair[1].getBytes()));
        String[] userPass =  decode.split(":");
        if(userPass.length != 2 && userPass[0].length() != 0 && userPass[1].length() != 0){
            // ユーザとパスワードの入力が無い場合
            return;
        }

        try{
            this.beforeAuthentication(request, response, userPass[0]);


            if(this.authentication(userPass[0], userPass[1], decode)){
                //ログイン成功の場合 次の処理へ渡す
                try{
                    this.beforeChain(request, userPass[0]);
                    chain.doFilter(servletRequest, servletResponse);
                }finally{
                    this.afterChain(request, response,  userPass[0]);
                }
            }else{
                // 認証に失敗した場合
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            }
        }finally{
            this.afterAuthentication(request, response,userPass[0]);
        }

    }

    /**
     * 認証処理前に呼び出されるメソッド
     * @param request クライアントからのリクエスト
     * @param response クライアントへのレスポンス
     * @param user ユーザ
     */
    public abstract void beforeAuthentication(HttpServletRequest request, HttpServletResponse response, String user);



    /**
     * 認証処理後chain等の全ての処理が終了した後に呼び出されるメソッド
     * @param request クライアントからのリクエスト
     * @param response クライアントへのレスポンス
     * @param user ユーザ
     */
    public abstract void afterAuthentication(HttpServletRequest request, HttpServletResponse response, String user);


    /**
     * 認証チェックする
     * @param user クライアントから送られてきたユーザ
     * @param password クライアントから送られてきたユーザのパスワード
     * @param decode user:passwordの文字列
     * @return 認証に成功した場合true
     */
    public abstract boolean authentication(String user, String password, String decode);


    /**
     * 認証成功時にchain前に呼ばれるメソッド
     * @param request クライアントからのリクエスト
     * @param user 認証に成功したユーザ
     */
    public abstract void beforeChain(HttpServletRequest request, String user);

    /**
     * 認証成功時にchain後に呼ばれるメソッド
     * @param request クライアントからのリクエスト
     * @param request サーバから送信するレスポンス
     * @param user 認証に成功したユーザ
     */
    public abstract void afterChain(HttpServletRequest request, HttpServletResponse response,  String user);


}
