const { 
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  GlobalSignOutCommand,
  CognitoIdentityProviderClient
} = require("@aws-sdk/client-cognito-identity-provider");
const crypto = require('crypto');
require('dotenv').config();

// 環境変数から設定を読み込み
const clientId = process.env.COGNITO_CLIENT_ID;
const clientSecret = process.env.COGNITO_CLIENT_SECRET;
const region = process.env.COGNITO_REGION;

// TEST_EMAIL=kuro.dougu1@gmail.com
// TEST_PASSWORD=Test123!@#
// 下記にはデフォルト値を設定   
const testEmail = process.env.TEST_EMAIL || 'test@example.com';
const testPassword = process.env.TEST_PASSWORD || 'Test123!@#';

// 環境変数の検証
if (!clientId || !clientSecret || !region) {
  throw new Error('Required environment variables are not set');
}

// Cognitoクライアントの初期化
const cognitoClient = new CognitoIdentityProviderClient({
  region: region
});

// ユーティリティ関数
const generateSecretHash = (username) => {
  const message = username + clientId;
  const hmac = crypto.createHmac('SHA256', clientSecret);
  return hmac.update(message).digest('base64');
};

const generateUsername = (email) => {
  if (!email) {
    throw new Error('メールアドレスが提供されていません');
  }
  return email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '');
};

const validatePassword = (password) => {
  if (password.length < 8) {
    return { isValid: false, error: 'パスワードは8文字以上である必要があります' };
  }
  if (!/[A-Z]/.test(password)) {
    return { isValid: false, error: 'パスワードには少なくとも1つの大文字を含める必要があります' };
  }
  if (!/[a-z]/.test(password)) {
    return { isValid: false, error: 'パスワードには少なくとも1つの小文字を含める必要があります' };
  }
  if (!/[0-9]/.test(password)) {
    return { isValid: false, error: 'パスワードには少なくとも1つの数字を含める必要があります' };
  }
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return { isValid: false, error: 'パスワードには少なくとも1つの記号を含める必要があります' };
  }
  return { isValid: true };
};

// メイン処理関数
async function signUp(email, password) {
  if (!password || !email) {
    throw new Error('password, emailは必須です');
  }

  const passwordValidation = validatePassword(password);
  if (!passwordValidation.isValid) {
    throw new Error(passwordValidation.error);
  }

  try {
    const username = generateUsername(email);
    const command = new SignUpCommand({
      ClientId: clientId,
      Username: username,
      Password: password,
      SecretHash: generateSecretHash(username),
      UserAttributes: [{ Name: 'email', Value: email }],
    });

    const data = await cognitoClient.send(command);
    console.log('ユーザー登録が成功しました:', {
      data,
      username,
      email
    });
    return data;
  } catch (error) {
    console.error('ユーザー登録に失敗しました:', error);
    throw error;
  }
}

async function confirmSignUp(email, code) {
  if (!email || !code) {
    throw new Error('メールアドレスと確認コードは必須です');
  }

  try {
    const username = generateUsername(email);
    const command = new ConfirmSignUpCommand({
      ClientId: clientId,
      Username: username,
      ConfirmationCode: code,
      SecretHash: generateSecretHash(username),
    });

    const data = await cognitoClient.send(command);
    console.log('ユーザー確認が成功しました:', {
      data,
      username,
      email
    });
    return data;
  } catch (error) {
    console.error('ユーザー確認に失敗しました:', error);
    throw error;
  }
}

// テスト実行
async function main() {
  try {
    // サインアップのテスト
    console.log('サインアップを開始します...');
    await signUp(testEmail, testPassword);
    
    // 確認コードの入力を促す
    console.log('確認コードをメールで受け取った後、以下のコードのコメントを解除して実行してください:');
    console.log('// await confirmSignUp(testEmail, "CONFIRMATION_CODE");');
    
  } catch (error) {
    console.error('エラーが発生しました:', error);
  }
}

main();
