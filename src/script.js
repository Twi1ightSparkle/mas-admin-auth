/*
Rudimentary client to authenticate as MAS+Synapse Admin with MAS.
Copyright (C) 2025  Twilight Sparkle

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>. 
*/

const clientDomain = document.URL.split('#')[0];

const copyValue = (elementId) => {
    const content = document.getElementById(elementId).value;
    navigator.clipboard.writeText(content);
    document.getElementById(`${elementId}_copied`).textContent = 'Copied!';
};

const setExpiry = (seconds) => {
    const hours = Math.round((seconds / 3600) * 10) / 10;
    const value = `${hours} hours (${seconds} seconds)`;
    document.getElementById('expires').textContent = value;
};

const setError = (error, type) => {
    document.getElementById(type).textContent = error;
};

generateString = (length) => {
    var result = '';
    var characters =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for (var i = 0; i < length; i++) {
        result += characters.charAt(
            Math.floor(Math.random() * charactersLength),
        );
    }
    return result;
};

const base64urlSHA256 = async (codeVerifier) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const bytes = new Uint8Array(hashBuffer);
    const binary = String.fromCharCode(...bytes);
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const discovery = async (serverDomain) => {
    const options = {
        method: 'GET',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
    };

    const url = `${serverDomain}/_matrix/client/unstable/org.matrix.msc2965/auth_metadata`;

    try {
        const response = await fetch(url, options);
        const data = await response.json();
        console.log(`discovery: data: ${JSON.stringify(data)}`);
        return data;
    } catch (error) {
        console.error(error);
        setError(
            `Failed to discover MAS endpoints on domain ${serverDomain}`,
            'auth_error',
        );
    }
};

const clientRegistration = async (registrationEndpoint) => {
    const body = JSON.stringify({
        application_type: 'web',
        client_name: 'MAS Admin Auth',
        client_uri: clientDomain,
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        redirect_uris: [clientDomain],
        response_types: ['code'],
    });
    const options = {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
    };

    try {
        const response = await fetch(registrationEndpoint, options);
        const data = await response.json();
        console.log(`registration: data: ${JSON.stringify(data)}`);
        return data;
    } catch (error) {
        console.error(error);
    }
};

const loginLink = async (authEndpoint, clientId) => {
    const authState = Date.now();
    const codeVerifier = generateString(50);
    const codeChallenge = await base64urlSHA256(codeVerifier);
    console.log(`loginLink: codeChallenge: ${codeChallenge}`);
    console.log(`loginLink: codeVerifier: ${codeVerifier}`);

    const authUrl =
        authEndpoint +
        `?response_type=code` +
        `&response_mode=fragment` +
        `&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(clientDomain)}` +
        `&scope=${encodeURIComponent(
            'urn:matrix:org.matrix.msc2967.client:api:* urn:mas:admin urn:synapse:admin:*',
        )}` +
        `&state=${authState}` +
        `&code_challenge_method=S256` +
        `&code_challenge=${codeChallenge}`;

    return { authUrl, codeVerifier };
};

const submit = async () => {
    setError('', 'auth_error');
    const serverDomain = document.getElementById('server_domain').value;
    localStorage.setItem('serverDomain', serverDomain);

    const discoveryData = await discovery(serverDomain);
    const { authorization_endpoint, registration_endpoint, token_endpoint } =
        discoveryData;
    localStorage.setItem('tokenEndpoint', token_endpoint);

    const registrationData = await clientRegistration(registration_endpoint);
    const { client_id } = registrationData;

    const { authUrl, codeVerifier } = await loginLink(
        authorization_endpoint,
        client_id,
    );
    console.log(`submit: authUrl: ${authUrl}`);
    localStorage.setItem('clientId', client_id);
    localStorage.setItem('codeVerifier', codeVerifier);
    const authAnchor = `<a href="${authUrl}"><button>Click to authenticate with MAS</button></a>`;
    document.getElementById('click_to_auth').innerHTML = authAnchor;
};

const exchangeCode = async (code, clientId, codeVerifier, tokenEndpoint) => {
    const options = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            code,
            grant_type: 'authorization_code',
            redirect_uri: clientDomain,
            client_id: clientId,
            code_verifier: codeVerifier,
        }),
    };

    try {
        const response = await fetch(tokenEndpoint, options);
        const data = await response.json();
        console.log(`exchangeCode: data: ${JSON.stringify(data)}`);
        return data;
    } catch (error) {
        console.error(error);
    }
};

const refresh = async () => {
    const refreshToken = document.getElementById('refresh_token').value;
    const clientId = document.getElementById('client_id').value;
    const tokenEndpoint = document.getElementById('token_endpoint').value;

    const options = {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: clientId,
            refresh_token: refreshToken,
        }),
    };

    let data;

    try {
        const response = await fetch(tokenEndpoint, options);
        data = await response.json();
        console.log(`refresh: data: ${JSON.stringify(data)}`);
    } catch (error) {
        console.error(error);
        setError(error, 'refresh_error');
        return 0;
    }

    if ('error' in data) {
        setError(data.error_description, 'refresh_error');
        return;
    }

    document.getElementById('access_token').value = data.access_token;
    document.getElementById('refresh_token').value = data.refresh_token;
    setExpiry(data.expires_in);
};

const onLoad = async () => {
    const hash = window.location.hash.substring(1);
    const params = new URLSearchParams(hash);
    const code = params.get('code');
    console.log(`onLoad: code: ${code}`);

    const clientId = localStorage.getItem('clientId');
    document.getElementById('client_id').value =
        clientId === 'undefined' ? '' : clientId;
    const serverDomain = localStorage.getItem('serverDomain');
    document.getElementById('server_domain').value =
        serverDomain === 'undefined' ? '' : serverDomain;
    const tokenEndpoint = localStorage.getItem('tokenEndpoint');
    document.getElementById('token_endpoint').value =
        tokenEndpoint === 'undefined' ? '' : tokenEndpoint;

    if (code === null) {
    } else {
        console.log('Got a code, exchanging it for an access token');
        const codeVerifier = localStorage.getItem('codeVerifier');
        const tokenEndpoint = localStorage.getItem('tokenEndpoint');
        const { access_token, refresh_token, expires_in } = await exchangeCode(
            code,
            clientId,
            codeVerifier,
            tokenEndpoint,
        );
        console.log(`onLoad: access_token: ${access_token}`);
        console.log(`onLoad: refresh_token: ${refresh_token}`);

        if (access_token === undefined) {
            return;
        }

        document.getElementById('access_token').value = access_token;
        document.getElementById('refresh_token').value = refresh_token;
        setExpiry(expires_in);
    }
};

window.onload = onLoad;
