import * as cdk from "@aws-cdk/core";
import * as cognito from "@aws-cdk/aws-cognito";
import * as iam from "@aws-cdk/aws-iam";
import * as lambda from "@aws-cdk/aws-lambda";
import * as ssm from "@aws-cdk/aws-ssm";
import * as sm from "@aws-cdk/aws-secretsmanager";
import * as acm from '@aws-cdk/aws-certificatemanager'
import * as route53 from '@aws-cdk/aws-route53'
import * as targets from "@aws-cdk/aws-route53-targets/lib";

export class Auth1Stack extends cdk.Stack {
  
  constructor(scope: cdk.Construct, id: string, props: cdk.StackProps) {
    super(scope, id, props);
    
    const BASENAME = this.node.tryGetContext('basename')
    
    //------------------read parameters from ssm parameter store and Secuity Manager
    
    const google_secret = sm.Secret.fromSecretNameV2(this, "google_secret", 
      this.node.tryGetContext('googleauth_smsecretname'))

    const GOOGLE_CLIENT_ID = google_secret
      .secretValueFromJson("GOOGLE_CLIENT_ID")
      .toString()
    const GOOGLE_CLIENT_SECRET = google_secret
      .secretValueFromJson("GOOGLE_CLIENT_SECRET")
      .toString()
      
    /*
    const cognito_login_urls = ssm.StringListParameter.fromStringListParameterName(...).stringListValue;
    のようにStringListParameterを使えば良いと思ったがdeploy時にエラーになる。
    const cognito_login_url = ssm.StringParameter.valueForTypedStringParameter(..., ParameterType.STRING_LIST);
    のようにStringListを使えば良いと思ったがこの場合もエラーになる。
    
    そこでStringParameterをカンマ区切りで登録して用意して以下のようにsplitすることにした。
    cdk.Fn.split(",", cognito_callback_url)
    
    fromStringParameterNameでも良いがこの場合は値を変更した際にchange setが作られない。
    valueForStringParameterはそれが作られる。バージョンを指定しなければ最新が適用される。
    
    2つの関数はtokenを使ってデプロイ時に値を解決するか、そうでないかという違いがあるのだろう。
    しかしそれがなぜこうした結果になるのか理由は知らない。
    fromStringParameterName: Imports an external string parameter by name.
    valueForStringParameter: Returns a token that will resolve (during deployment)...
    
    実際のところvalueForStringParameterを使い始めて感じたのはSSMのパラメータを
    削除してしまったりすると厄介だということだ。これは必要に応じて
    */
    
    const COGNITO_CALLBACK_URLS = ssm.StringParameter.valueFromLookup(this, 
      this.node.tryGetContext('cognito_userpool_appclient_callbackurls_ssmparamname')
    )
    
    const COGNITO_LOGIN_URLS = ssm.StringParameter.valueFromLookup(this, 
      this.node.tryGetContext('cognito_userpool_appclient_sighouturls_ssmparamname')
    )

    const ALLOWED_EMAILS = ssm.StringParameter.valueFromLookup(this, 
      this.node.tryGetContext('cognito_userpool_signuptrigger_allowedemails_ssmparamname')
    )
    
    const ALLOWED_DOMAINS = ssm.StringParameter.valueFromLookup(this, 
      this.node.tryGetContext('cognito_userpool_signuptrigger_alloweddomains_ssmparamname')
    )
    
    const DOMAINNAME = ssm.StringParameter.valueFromLookup(this, 
      this.node.tryGetContext('cognito_userpool_domainname_ssmparamname')
    )
    
    const SUBDOMAINNAME = ssm.StringParameter.valueFromLookup(this, 
      this.node.tryGetContext('cognito_userpool_subdomainname_ssmparamname')
    )
    
    const FQDN = ssm.StringParameter.valueFromLookup(this, 
      this.node.tryGetContext('cognito_userpool_fqdn_ssmparamname')
    )
    
    const HOSTEDZONEID = cdk.Fn.importValue(this.node.tryGetContext('hostedzoneid_exportname'))
 
    const ACMARN = acm.Certificate.fromCertificateArn(this, 'acmarn', 
      cdk.Fn.importValue(this.node.tryGetContext('notrhvirginia_acmarn_exportname'))
    )

    // Lambda Sign Up Trigger

    const trigger_function = new lambda.Function(this, "lambda_function", {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset("lambda"),
      handler: "signup_trigger.lambda_handler",
      environment: {
        ALLOWED_EMAILS: ALLOWED_EMAILS,
        ALLOWED_DOMAINS: ALLOWED_DOMAINS
      }
    });

    // Cognito User Pool with Google idP

    const user_pool = new cognito.UserPool(this, "user_pool", {
      selfSignUpEnabled: false,
      userPoolName: BASENAME + "-userpool",
      lambdaTriggers: {
        preSignUp: trigger_function,
      },
    });

    const google_idp = new cognito.UserPoolIdentityProviderGoogle(
      this,
      "user_pool_idp_google",
      {
        clientId: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        userPool: user_pool,
        scopes: ["profile", "email", "openid"],
        attributeMapping: {
          email: cognito.ProviderAttribute.GOOGLE_EMAIL,
        },
      }
    );

    // Cognito User Pool Settings
    
    // よくわからないのだが、ネイキッドドメインに何らかの（何でもいいと思うのだがAレコードが必要）
    // そうでないとcdk deploy時にこんなエラーが出る。
    // Custom domain is not a valid subdomain: Was not able to resolve the root domain, please ensure an A record exists for the root domain.
    // とりあえずAレコードはこれのためだけに手で作った。（このcdkでデプロイしていない）
    
    const userpool_domain = new cognito.UserPoolDomain(this, "user_pool_domain", {
      userPool: user_pool,
      customDomain: {
        domainName: FQDN,
        certificate: ACMARN
      }
    })
    
    const zone = route53.HostedZone.fromHostedZoneAttributes(this, "zone", {
      hostedZoneId: HOSTEDZONEID,
      zoneName: DOMAINNAME
    })
    
    const record = new route53.ARecord(this, 'record', {
      zone: zone,
      recordName: SUBDOMAINNAME,
      target: route53.RecordTarget.fromAlias(new targets.UserPoolDomainTarget(userpool_domain)),
    })
    
    const oauth_settings = {
      callbackUrls: cdk.Fn.split(",", COGNITO_CALLBACK_URLS),
      logoutUrls: cdk.Fn.split(",", COGNITO_LOGIN_URLS),
      flows: {
        authorizationCodeGrant: true,
        clientCredentials: false,
        implicitCodeGrant: true,
      },
      scopes: [
        cognito.OAuthScope.EMAIL,
        cognito.OAuthScope.OPENID,
        cognito.OAuthScope.PROFILE,
        cognito.OAuthScope.COGNITO_ADMIN,
      ],
    };

    const user_pool_client_web = new cognito.UserPoolClient(
      this,
      "user_pool_client_web",
      {
        userPool: user_pool,
        generateSecret: false,
        // userPoolClientName: BASENAME + "-userpool-client-web",
        supportedIdentityProviders: [
          cognito.UserPoolClientIdentityProvider.GOOGLE,
        ],
        oAuth: oauth_settings,
      }
    );
    
    const user_pool_client_native = new cognito.UserPoolClient(
      this,
      "user_pool_client_native",
      {
        userPool: user_pool,
        generateSecret: true,
        // userPoolClientName: BASENAME + "-userpool-client-native",
        supportedIdentityProviders: [
          cognito.UserPoolClientIdentityProvider.GOOGLE,
        ],
        oAuth: oauth_settings,
      }
    );
    
    const google_idp_dependable = new cdk.ConcreteDependable();
    google_idp_dependable.add(google_idp);
    user_pool_client_web.node.addDependency(google_idp_dependable);
    user_pool_client_native.node.addDependency(google_idp_dependable);
    
    // Cognito Id Pool

    const id_pool = new cognito.CfnIdentityPool(this, "id_pool", {
      allowUnauthenticatedIdentities: true,
      cognitoIdentityProviders: [
        {
          clientId: user_pool_client_web.userPoolClientId,
          providerName: user_pool.userPoolProviderName,
          serverSideTokenCheck: false,
        },
        {
          clientId: user_pool_client_native.userPoolClientId,
          providerName: user_pool.userPoolProviderName,
          serverSideTokenCheck: false,
        },
      ],
      identityPoolName: BASENAME + "-idpool",
    });

    // Id Pool IAM Roles
    
    const iam_authenticated_role = new iam.Role(this, "iam_auth_role", {
      assumedBy: new iam.FederatedPrincipal(
        "cognito-identity.amazonaws.com",
        {
          StringEquals: {
            "cognito-identity.amazonaws.com:aud": id_pool.ref,
          },
          "ForAnyValue:StringLike": {
            "cognito-identity.amazonaws.com:amr": "authenticated",
          },
        },
        "sts:AssumeRoleWithWebIdentity"
      ),
      roleName: BASENAME + "-authenticated-role",
    });

    const iam_unauthenticated_role = new iam.Role(this, "iam_unauth_role", {
      assumedBy: new iam.FederatedPrincipal(
        "cognito-identity.amazonaws.com",
        {
          StringEquals: {
            "cognito-identity.amazonaws.com:aud": id_pool.ref,
          },
          "ForAnyValue:StringLike": {
            "cognito-identity.amazonaws.com:amr": "unauthenticated",
          },
        },
        "sts:AssumeRoleWithWebIdentity"
      ),
      roleName: BASENAME + "-unauthenticated-role",
    });

    new cognito.CfnIdentityPoolRoleAttachment(this, "id_pool_role_attach", {
      identityPoolId: id_pool.ref,
      roles: {
        authenticated: iam_authenticated_role.roleArn,
        unauthenticated: iam_unauthenticated_role.roleArn,
      },
    });
    
    // output
    
    new ssm.StringParameter(this, 'cognito_idpool_id_ssmparamname', {
      parameterName: this.node.tryGetContext('cognito_idpool_id_ssmparamname'),
      stringValue: id_pool.ref,
    })
    
    new ssm.StringParameter(this, 'cognito_userpool_id_ssmparamname', {
      parameterName: this.node.tryGetContext('cognito_userpool_id_ssmparamname'),
      stringValue: user_pool.userPoolId,
    })
    
    new ssm.StringParameter(this, 'cognito_userpool_appclientforwebid_ssmparamname', {
      parameterName: this.node.tryGetContext('cognito_userpool_webclient_id_ssmparamname'),
      stringValue: user_pool_client_web.userPoolClientId,
    })
    
    new cdk.CfnOutput(this, 'idpoolid', {
      exportName: this.node.tryGetContext('cognito_idpool_id_exportname'), 
      value: id_pool.ref
    })
    new cdk.CfnOutput(this, 'userpoolid', {
      exportName: this.node.tryGetContext('cognito_userpool_id_exportname'), 
      value: user_pool.userPoolId
    })
    new cdk.CfnOutput(this, 'webclientid', {
      exportName: this.node.tryGetContext('cognito_userpool_webclient_id_exportname'), 
      value: user_pool_client_web.userPoolClientId
    })
    new cdk.CfnOutput(this, 'domainname', {
      exportName: this.node.tryGetContext('cognito_userpool_fqdn_exportname'), 
      value: userpool_domain.domainName
    })
    new cdk.CfnOutput(this, 'auth_iamrolearn', {
      exportName: this.node.tryGetContext('cognito_idpool_auth_iamrolearn_exportname'), 
      value: iam_authenticated_role.roleArn
    })
    new cdk.CfnOutput(this, 'unauth_iamrolearn', {
      exportName: this.node.tryGetContext('cognito_idpool_unauth_iamrolearn_exportname'), 
      value: iam_unauthenticated_role.roleArn
    })
  }
}
