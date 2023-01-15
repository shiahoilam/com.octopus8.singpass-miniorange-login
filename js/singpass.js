async function init() {
    const clientId = singpass_vars.clientId;
    const redirectUri = singpass_vars.redirectUri;
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
            clientId: clientId, // Replace with your client ID
            redirectUri: redirectUri,        // Replace with a registered redirect URI
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


 window.onload = init;