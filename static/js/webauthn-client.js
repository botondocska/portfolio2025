// WebAuthn Client-Side JavaScript
// Based on webauthn-rs WASM implementation for accuracy and safety

class WebAuthnClient {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl;
    }

    // Convert base64url to ArrayBuffer (used for challenge, id, etc.)
    base64urlToBuffer(base64url) {
        // Add padding if needed
        const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
        const base64 = (base64url + padding)
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        
        const rawData = atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        
        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray.buffer;
    }

    // Convert ArrayBuffer to base64url (for sending to server)
    bufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    // Register a new passkey
    async register(username) {
        try {
            // Step 1: Start registration - get challenge from server
            console.log('Starting registration for:', username);
            
            const startResponse = await fetch(`${this.baseUrl}/register_start/${encodeURIComponent(username)}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                mode: 'same-origin',
            });

            if (!startResponse.ok) {
                const errorText = await startResponse.text();
                throw new Error(errorText || `Server error: ${startResponse.status}`);
            }

            const creationOptions = await startResponse.json();
            console.log('Received creation challenge:', creationOptions);

            // Step 2: Convert server response to browser-compatible format
            // The server sends base64url encoded data that needs to be converted to ArrayBuffers
            const publicKeyCredentialCreationOptions = {
                challenge: this.base64urlToBuffer(creationOptions.publicKey.challenge),
                rp: creationOptions.publicKey.rp,
                user: {
                    id: this.base64urlToBuffer(creationOptions.publicKey.user.id),
                    name: creationOptions.publicKey.user.name,
                    displayName: creationOptions.publicKey.user.displayName,
                },
                pubKeyCredParams: creationOptions.publicKey.pubKeyCredParams,
                timeout: creationOptions.publicKey.timeout,
                attestation: creationOptions.publicKey.attestation,
                authenticatorSelection: creationOptions.publicKey.authenticatorSelection,
            };

            // Handle excludeCredentials if present (prevents re-registering same credential)
            if (creationOptions.publicKey.excludeCredentials) {
                publicKeyCredentialCreationOptions.excludeCredentials = 
                    creationOptions.publicKey.excludeCredentials.map(cred => ({
                        type: cred.type,
                        id: this.base64urlToBuffer(cred.id),
                        transports: cred.transports,
                    }));
            }

            // Step 3: Ask browser to create credential
            console.log('Calling navigator.credentials.create...');
            const credential = await navigator.credentials.create({
                publicKey: publicKeyCredentialCreationOptions
            });

            if (!credential) {
                throw new Error('Failed to create credential - no credential returned');
            }

            console.log('Credential created:', credential);

            // Step 4: Convert credential to format server expects
            // This matches the RegisterPublicKeyCredential struct from webauthn-rs-proto
            const credentialForServer = {
                id: credential.id,
                rawId: this.bufferToBase64url(credential.rawId),
                type: credential.type,
                response: {
                    attestationObject: this.bufferToBase64url(credential.response.attestationObject),
                    clientDataJSON: this.bufferToBase64url(credential.response.clientDataJSON),
                },
                // Include extensions if present
                extensions: credential.getClientExtensionResults ? 
                    credential.getClientExtensionResults() : {},
            };

            console.log('Sending credential to server:', credentialForServer);

            // Step 5: Send credential to server for verification
            const finishResponse = await fetch(`${this.baseUrl}/register_finish`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                mode: 'same-origin',
                body: JSON.stringify(credentialForServer)
            });

            if (!finishResponse.ok) {
                const errorText = await finishResponse.text();
                throw new Error(errorText || `Registration failed: ${finishResponse.status}`);
            }

            console.log('Registration successful!');
            return { success: true, message: 'Registration successful!' };

        } catch (error) {
            console.error('Registration error:', error);
            return { 
                success: false, 
                message: error.message || error.toString() 
            };
        }
    }

    // Authenticate with existing passkey
    async authenticate(username) {
        try {
            // Step 1: Start authentication - get challenge from server
            console.log('Starting authentication for:', username);
            
            const startResponse = await fetch(`${this.baseUrl}/login_start/${encodeURIComponent(username)}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                mode: 'same-origin',
            });

            if (!startResponse.ok) {
                const errorText = await startResponse.text();
                throw new Error(errorText || `Server error: ${startResponse.status}`);
            }

            const requestOptions = await startResponse.json();
            console.log('Received authentication challenge:', requestOptions);

            // Step 2: Convert server response to browser-compatible format
            const publicKeyCredentialRequestOptions = {
                challenge: this.base64urlToBuffer(requestOptions.publicKey.challenge),
                timeout: requestOptions.publicKey.timeout,
                rpId: requestOptions.publicKey.rpId,
                allowCredentials: requestOptions.publicKey.allowCredentials.map(cred => ({
                    type: cred.type,
                    id: this.base64urlToBuffer(cred.id),
                    transports: cred.transports,
                })),
                userVerification: requestOptions.publicKey.userVerification,
            };

            // Step 3: Ask browser to get credential (authenticate)
            console.log('Calling navigator.credentials.get...');
            const assertion = await navigator.credentials.get({
                publicKey: publicKeyCredentialRequestOptions
            });

            if (!assertion) {
                throw new Error('Failed to get credential - no assertion returned');
            }

            console.log('Assertion received:', assertion);

            // Step 4: Convert assertion to format server expects
            // This matches the PublicKeyCredential struct from webauthn-rs-proto
            const assertionForServer = {
                id: assertion.id,
                rawId: this.bufferToBase64url(assertion.rawId),
                type: assertion.type,
                response: {
                    authenticatorData: this.bufferToBase64url(assertion.response.authenticatorData),
                    clientDataJSON: this.bufferToBase64url(assertion.response.clientDataJSON),
                    signature: this.bufferToBase64url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? 
                        this.bufferToBase64url(assertion.response.userHandle) : null,
                },
                // Include extensions if present
                extensions: assertion.getClientExtensionResults ? 
                    assertion.getClientExtensionResults() : {},
            };

            console.log('Sending assertion to server:', assertionForServer);

            // Step 5: Send assertion to server for verification
            const finishResponse = await fetch(`${this.baseUrl}/login_finish`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                mode: 'same-origin',
                body: JSON.stringify(assertionForServer)
            });

            if (!finishResponse.ok) {
                const errorText = await finishResponse.text();
                throw new Error(errorText || `Authentication failed: ${finishResponse.status}`);
            }

            console.log('Authentication successful!');
            return { success: true, message: 'Authentication successful!' };

        } catch (error) {
            console.error('Authentication error:', error);
            return { 
                success: false, 
                message: error.message || error.toString() 
            };
        }
    }

    // Check if WebAuthn is supported in this browser
    static isSupported() {
        return window.PublicKeyCredential !== undefined &&
               navigator.credentials !== undefined &&
               typeof navigator.credentials.create === 'function' &&
               typeof navigator.credentials.get === 'function';
    }

    // Check if conditional mediation is available (for autofill)
    static async isConditionalMediationAvailable() {
        if (!WebAuthnClient.isSupported()) {
            return false;
        }
        
        try {
            const available = await PublicKeyCredential.isConditionalMediationAvailable();
            return available;
        } catch (e) {
            return false;
        }
    }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WebAuthnClient;
}