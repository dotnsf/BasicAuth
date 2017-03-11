package me.juge.basicauth;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.sun.xml.internal.messaging.saaj.packaging.mime.internet.MimeUtility;

public class BasicAuthenticationFilter implements Filter{
	//. レルム名
    private final String realmName = "myRealm";
 

    //. Filter の実装に必要なメソッド（何もしない）
    public void init( FilterConfig config ) throws ServletException{
    }
    public void destroy(){
    }

    //. フィルタリング処理の実装
    public void doFilter( ServletRequest req, ServletResponse res, FilterChain filterChain ) throws IOException, ServletException{
        ByteArrayInputStream bin = null;
        BufferedReader br = null;
        
        boolean isAuthorized = false; //. この値で認証の可否を判断する
        try{
            HttpServletRequest httpReq = ( HttpServletRequest )req;
            String basicAuthData = httpReq.getHeader( "authorization" );
            if( basicAuthData != null && basicAuthData.length() > 6 ){
                //. Basic認証から情報を取得
                String basicAuthBody = basicAuthData.substring( 6 ); //. 'Basic dG9tY2F0OnRvbWNhdA== ' 

                //. BASE64 デコード
                bin = new ByteArrayInputStream( basicAuthBody.getBytes() ); 
                br = new BufferedReader( new InputStreamReader( MimeUtility.decode( bin, "base64" ) ) );
                StringBuilder buf = new StringBuilder();
                String line = null;
                while ( ( line = br.readLine() )!=null ) {
                    buf.append( line );
                }
                
                //. 入力された username と password を取り出す
                String[] loginInfo = buf.toString().split( ":" );
                String username = loginInfo[0];
                String password = loginInfo[1];
//.             System.out.println( "Basic " + username + ":" + password );

                //. 取り出した username と password で認証可否を判断する
                
                //. 実際にはここで LDAP やユーザー情報データベースと比較して判断することになる
                isAuthorized = true; //. 今回の例ではとりあえず何かが入力されていれば認証 OK とする
            }
            
            if( !isAuthorized ){
                //. （認証に何も指定されていなかった場合も含めて）認証 NG だった場合はブラウザに UnAuthorized エラー(401)を返す
                HttpServletResponse httpRes = ( HttpServletResponse )res;
                httpRes.setHeader( "WWW-Authenticate", "Basic realm=" + this.realmName );
                httpRes.setContentType( "text/html" );
                httpRes.sendError( HttpServletResponse.SC_UNAUTHORIZED ); //. 401
                
                //. 最初に認証なしでアクセスした場合はここを通るので、その結果ブラウザが認証ダイアログを出す、という流れ
            }else{
            	//. 認証 OK だった場合はそのまま処理を続ける
                filterChain.doFilter( req, res );
            }
        }catch( Exception e ){
            throw new ServletException( e );
        }finally{
        	//. ストリームのクローズ
            try{
                if( bin!=null ) bin.close();
                if( br !=null ) br.close();
            }catch( Exception e ){
            }
        }
    }
}
