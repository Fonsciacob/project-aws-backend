import { Injectable } from '@nestjs/common';
import {
  AuthenticationDetails,
  CognitoUser,
  CognitoUserPool,
} from 'amazon-cognito-identity-js';
import { Response } from 'express';

@Injectable()
export class AppService {
  private userPool: CognitoUserPool;
  private newUser: CognitoUser;

  constructor() {
    this.userPool = new CognitoUserPool({
      UserPoolId: 'us-east-1_L1ZpzoxWE',
      ClientId: 'edm0oegkkpcj3fvlj0r10j7k4',
    });
  }

  authenticated(credentials, response: Response) {
    const { email, password } = credentials;

    const authenticationDetails = new AuthenticationDetails({
      Username: email,
      Password: password,
    });

    const userData = {
      Username: email,
      Pool: this.userPool,
    };

    this.newUser = new CognitoUser(userData);
    const user = this.newUser;
    return user.authenticateUser(authenticationDetails, {
      /*** Callbacks ***/
      newPasswordRequired(userAttributes, requiredAttributes) {
        return response.json({ requiredNewPassword: true });
      },

      mfaSetup(challengeName, challengeParameters) {
        user.associateSoftwareToken({
          associateSecretCode: (secretCode) => {
            if (challengeName === 'MFA_SETUP') {
              const url = `otpauth://totp/${user.getUsername()}?secret=${secretCode}&issuer=Cognito-TOTP-MFA`;
              return response.json({ url: url, setupMfa: true });
            }
          },
          onFailure: (err: Error) => {
            return response.json(err.message);
          },
        });
      },

      totpRequired(challengeName, challengeParameters) {
        if (challengeName === 'SOFTWARE_TOKEN_MFA') {
          return response.json({ requiredTotp: true });
        }
      },
      onSuccess: (result) => {
        return response.json(result);
      },
      onFailure: (err: Error) => {
        return response.status(500).json({ error: err.message });
      },
    });
  }

  async newPasswordReq(credentials, response: Response) {
    const { newPassword } = credentials;
    const user = this.newUser;
    this.newUser.completeNewPasswordChallenge(newPassword, null, {
      mfaSetup(challengeName) {
        user.associateSoftwareToken({
          associateSecretCode: (secretCode) => {
            if (challengeName === 'MFA_SETUP') {
              const url = `otpauth://totp/${user.getUsername()}?secret=${secretCode}&issuer=Cognito-TOTP-MFA`;
              return response.json({ url: url, setupMfa: true });
            }
          },
          onFailure: (err: Error) => {
            return response.json(err.message);
          },
        });
      },
      onSuccess: (result) => {
        return response.json(result);
      },
      onFailure: (err: Error) => {
        return response.json(err.message);
      },
    });
  }

  async setupMFA(code) {
    return new Promise((resolve, reject) => {
      this.newUser.verifySoftwareToken(`${code.codeTotp}`, '', {
        onSuccess: function (result) {
          resolve(result);
        },
        onFailure: function (err) {
          reject(err);
        },
      });
    });
  }

  async totpReq(code) {
    return new Promise((resolve, reject) => {
      this.newUser.sendMFACode(
        `${code.codeTotp}`,
        {
          onSuccess: (result) => {
            resolve(result);
          },
          onFailure: (err) => {
            reject(err);
          },
        },
        'SOFTWARE_TOKEN_MFA',
      );
    });
  }
}
