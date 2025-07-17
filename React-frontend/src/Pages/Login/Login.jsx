import { useState } from 'react';
import { useDispatch } from 'react-redux';
import { setAuthCookies, signInUser } from '../../api/auth';
import { loggedInUserSlice } from '../../Store/Slices';
import Input from "../../Components/Input/Input";
import Snackbar from '../../Components/Snackbar/Snackbar';
import { styled } from '@mui/system';

// Styled components
const LoginContainer = styled('div')`
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: linear-gradient(135deg, #000000 0%, #1b254f 100%);
  padding: 1rem;
`;

const LoginCard = styled('div')`
  background: rgba(13, 17, 38, 0.85);
  backdrop-filter: blur(10px);
  border-radius: 16px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
  overflow: hidden;
  min-width: 430px;
  width: fit;
  padding: 2.5rem;
  
  @media (max-width: 480px) {
    padding: 2rem 1.5rem;
    max-width: 90%;
  }
`;

const FormTitle = styled('h1')`
  color: white;
  text-align: center;
  font-size: 1.75rem;
  font-weight: 600;
  margin-bottom: 1.5rem;
`;

const Form = styled('form')`
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
`;

const InputContainer = styled('div')`
  width: 100%;
`;

const ErrorMessage = styled('p')`
  color: #ff5b5b;
  font-size: 0.875rem;
  margin-top: 0.5rem;
  text-align: left;
`;

const LoginButton = styled('button')`
  background: linear-gradient(90deg, #2a3aad 0%, #4b59cf 100%);
  color: white;
  border: none;
  border-radius: 8px;
  padding: 0.85rem;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
  margin-top: 1rem;
  
  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(42, 58, 173, 0.4);
  }
  
  &:active {
    transform: translateY(0);
    box-shadow: 0 2px 6px rgba(42, 58, 173, 0.3);
  }
  
  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
  }
`;

const VerifyLoginButton = styled('button')`
  background: linear-gradient(90deg, #2a3aad 0%, #4b59cf 100%);
  color: white;
  border: none;
  border-radius: 8px;
  padding: 0.85rem;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
  margin-top: 1rem;
  width: 100px;
  
  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(42, 58, 173, 0.4);
  }
  
  &:active {
    transform: translateY(0);
    box-shadow: 0 2px 6px rgba(42, 58, 173, 0.3);
  }
  
  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
  }
`;

const BackButton = styled('button')`
  background: transparent;
  color: #8b9dc3;
  border: 1px solid #8b9dc3;
  border-radius: 8px;
  padding: 0.85rem;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
  margin-top: 1rem;
  
  &:hover {
    background: rgba(139, 157, 195, 0.1);
    color: white;
    border-color: white;
  }
`;

const QRContainer = styled('div')`
  display: flex;
  gap: 2rem;
  margin: 1.5rem 0;
  align-items: flex-start;
  
  @media (max-width: 480px) {
    flex-direction: column;
    align-items: center;
    gap: 1.5rem;
  }
`;

const QRCodeImage = styled('img')`
  width: 180px;
  height: 180px;
  border-radius: 8px;
  background: white;
  padding: 10px;
  flex-shrink: 0;
`;

const InstructionText = styled('div')`
  color: #8b9dc3;
  font-size: 0.875rem;
  line-height: 1.5;
  text-align: center;
`;

const InstructionTitle = styled('h3')`
  color: white;
  font-size: 1.1rem;
  font-weight: 600;
  margin-bottom: 1rem;
  text-align: left;
  
  @media (max-width: 480px) {
    text-align: center;
  }
`;

const StepList = styled('ol')`
  color: #8b9dc3;
  font-size: 0.875rem;
  line-height: 1.6;
  padding-left: 1.2rem;
  margin: 0;
  
  li {
    margin-bottom: 0.8rem;
  }
`;

const InstructionContainer = styled('div')`
  flex: 1;
  min-width: 0;
`;

const ButtonContainer = styled('div')`
  display: flex;
  gap: 1.1rem;
  margin-top: 1rem;
  width: full;
  flex-direction: row;
  
  @media (max-width: 480px) {
    flex-direction: column;
    gap:1rem;
  }
`;

const TOTPInput = styled('input')`
  width: 100%;
  padding: 0.85rem;
  font-size: 1.2rem;
  text-align: center;
  letter-spacing: 0.5rem;
  border: 2px solid #2a3aad;
  border-radius: 8px;
  background: rgba(42, 58, 173, 0.1);
  color: white;
  outline: none;
  transition: border-color 0.2s ease;
  
  &:focus {
    border-color: #4b59cf;
  }
  
  &::placeholder {
    color: #8b9dc3;
    letter-spacing: normal;
  }
`;

const Login = () => {
    const dispatch = useDispatch();
    const [step, setStep] = useState('login'); // 'login', 'setup', 'verify'
    const [userCreds, setUserCreds] = useState({
        email: "",
        password: "",
    });
    const [totpToken, setTotpToken] = useState("");
    const [qrCode, setQrCode] = useState("");
    const [errorMsg, setErrorMsg] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [totpEnabled, setTotpEnabled] = useState(false);

    const [openSnackbar, setOpenSnackbar] = useState(false);
    const [snackbarDetails, setSnackbarDetails] = useState({
        type: "",
        message: ""
    });

    const handleLogin = async (e) => {
        e?.preventDefault();

        if (userCreds.email === "" || userCreds.password === "") {
            setSnackbarDetails({
                type: "error",
                message: "Please enter email and password"
            });
            setOpenSnackbar(true);
            return;
        }

        setIsLoading(true);
        setErrorMsg("");

        try {
            const response = await signInUser({
                email: userCreds.email,
                password: userCreds.password,
            });

            if (response.requires_totp) {
                setQrCode(response.qr_code);
                setTotpEnabled(response.totp_enabled);

                if (response.totp_enabled) {
                    setStep('verify');
                } else {
                    setStep('setup');
                }
            } else {
                // Regular login without TOTP
                await completeLogin(response);
            }
        } catch (error) {
            setErrorMsg(error.response?.data?.error || "Login failed. Please try again.");
        } finally {
            setIsLoading(false);
        }
    };

    const handleTOTPSetup = async (e) => {
        e?.preventDefault();

        if (totpToken.length !== 6) {
            setSnackbarDetails({
                type: "error",
                message: "Please enter a valid 6-digit code"
            });
            setOpenSnackbar(true);
            return;
        }

        setIsLoading(true);
        setErrorMsg("");

        try {
            const response = await fetch('http://127.0.0.1:8000/api/v1/login/totp/setup/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: userCreds.email,
                    totp_token: totpToken
                })
            });

            const data = await response.json();

            if (response.ok) {
                await completeLogin(data);
            } else {
                setErrorMsg(data.error || "TOTP setup failed. Please try again.");
            }
        } catch (error) {
            setErrorMsg("TOTP setup failed. Please try again.");
        } finally {
            setIsLoading(false);
        }
    };

    const handleTOTPVerify = async (e) => {
        e?.preventDefault();

        if (totpToken.length !== 6) {
            setSnackbarDetails({
                type: "error",
                message: "Please enter a valid 6-digit code"
            });
            setOpenSnackbar(true);
            return;
        }

        setIsLoading(true);
        setErrorMsg("");

        try {
            const response = await fetch('http://127.0.0.1:8000/api/v1/login/totp/verify/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: userCreds.email,
                    totp_token: totpToken
                })
            });

            const data = await response.json();

            if (response.ok) {
                await completeLogin(data);
            } else {
                setErrorMsg(data.error || "Invalid code. Please try again.");
            }
        } catch (error) {
            setErrorMsg("Verification failed. Please try again.");
        } finally {
            setIsLoading(false);
        }
    };

    const completeLogin = async (userData) => {
        setAuthCookies({
            name: userData.name || "",
            username: userData.username || "",
            email: userData.email || "",
            refreshToken: userData.refresh,
            accessToken: userData.access,
            expiry: 0,
        });

        dispatch(
            loggedInUserSlice.actions.setLogedInUserData({
                name: userData.name || "",
                username: userData.username || "",
                email: userData.email || "",
                refreshToken: userData.refresh,
                accessToken: userData.access,
            })
        );

        setSnackbarDetails({
            type: "success",
            message: "Login successful!"
        });
        setOpenSnackbar(true);

        window.location.href = "/";
    };

    const handleChange = (keyName, keyValue) => {
        setUserCreds({
            ...userCreds,
            [keyName]: keyValue
        });
        if (errorMsg) setErrorMsg("");
    };

    const handleTOTPChange = (e) => {
        const value = e.target.value.replace(/\D/g, '').slice(0, 6);
        setTotpToken(value);
        if (errorMsg) setErrorMsg("");
    };

    const handleBackToLogin = () => {
        setStep('login');
        setTotpToken("");
        setQrCode("");
        setErrorMsg("");
    };

    const handleNextAfterQR = () => {
        setStep('verify');
    };

    const renderLogin = () => (
        <>
            <FormTitle>Sign in</FormTitle>
            <Form onSubmit={handleLogin}>
                <InputContainer>
                    <Input
                        label="email"
                        placeholder="Email Address"
                        value={userCreds.email}
                        handleChange={handleChange}
                    />
                </InputContainer>

                <InputContainer>
                    <Input
                        type="password"
                        label="password"
                        placeholder="Password"
                        value={userCreds.password}
                        handleChange={handleChange}
                    />
                    {errorMsg && <ErrorMessage>{errorMsg}</ErrorMessage>}
                </InputContainer>

                <LoginButton
                    type="submit"
                    disabled={isLoading}
                >
                    {isLoading ? "Signing in..." : "Sign in"}
                </LoginButton>
            </Form>
        </>
    );

    const renderSetup = () => (
        <>
            <FormTitle>Set up Authenticator</FormTitle>
            <QRContainer>
                <QRCodeImage src={qrCode} alt="QR Code for Authenticator Setup" />
                <InstructionContainer>
                    <InstructionTitle>Setup Instructions</InstructionTitle>
                    <StepList>
                        <li>Install an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator</li>
                        <li>Open the app and tap "Add Account" or "+"</li>
                        <li>Scan the QR code with your phone's camera</li>
                        <li>Your authenticator app will generate a 6-digit code</li>
                        <li>Click "Next" below to enter the code</li>
                    </StepList>
                </InstructionContainer>
            </QRContainer>
            <ButtonContainer>
                <BackButton onClick={handleBackToLogin}>
                    Back to Login
                </BackButton>
                <LoginButton onClick={handleNextAfterQR}>
                    Next
                </LoginButton>
            </ButtonContainer>
        </>
    );

    const renderVerify = () => (
        <>
            <FormTitle>
                {totpEnabled ? "Enter Authentication Code" : "Verify Setup"}
            </FormTitle>
            <InstructionText>
                {totpEnabled
                    ? "Enter the 6-digit code from your authenticator app"
                    : "Enter the 6-digit code from your authenticator app to complete setup"
                }
            </InstructionText>
            <Form onSubmit={totpEnabled ? handleTOTPVerify : handleTOTPSetup}>
                <InputContainer>
                    <TOTPInput
                        type="text"
                        value={totpToken}
                        onChange={handleTOTPChange}
                        placeholder="000000"
                        maxLength="6"
                    />
                    {errorMsg && <ErrorMessage>{errorMsg}</ErrorMessage>}
                </InputContainer>

                <ButtonContainer>
                    <BackButton onClick={handleBackToLogin}>
                        Back to Login
                    </BackButton>
                    <VerifyLoginButton
                        type="submit"
                        disabled={isLoading || totpToken.length !== 6}
                    >
                        {isLoading ? "Verifying..." : "Verify"}
                    </VerifyLoginButton>
                </ButtonContainer>
            </Form>
        </>
    );

    return (
        <LoginContainer>
            <Snackbar
                openSnackbar={openSnackbar}
                setOpenSnackbar={setOpenSnackbar}
                type={snackbarDetails.type}
                message={snackbarDetails.message}
            />

            <LoginCard>
                {step === 'login' && renderLogin()}
                {step === 'setup' && renderSetup()}
                {step === 'verify' && renderVerify()}
            </LoginCard>
        </LoginContainer>
    );
};

export default Login;