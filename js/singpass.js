async function init() {
    const authParamsSupplier = async () => {
        // Replace the below with an `await`ed call to initiate an auth session on your backend
        // which will generate state+nonce values, e.g
        const state = singpass_vars.state;
        return { state: state, nonce: state };
    };

    const onError = (errorId, message) => {
        console.log(`onError. errorId:${errorId} message:${message}`);
    };

    const initAuthSessionResponse = window.NDI.initAuthSession(
        'ndi-qr',
        {
            clientId: 'hCqn1a2gQFi6QLPeaw3LIWP3LQ2E5f0r', // Replace with your client ID
            redirectUri: 'https://asliddin.socialservicesconnect.com/wp-json/singpass/v1/signin_oidc',        // Replace with a registered redirect URI
            scope: 'openid',
            responseType: 'code'
        },
        authParamsSupplier,
        onError,
        {
            renderDownloadLink: true,
            appLaunchUrl: 'https://partner.gov.sg', // Replace with your iOS/Android App Link,
            uiLocale: 'ms'
        },
    );

    console.log('initAuthSession: ', initAuthSessionResponse);
}

function createUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
       var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
       return v.toString(16);
    });
 }
 window.onload = init;