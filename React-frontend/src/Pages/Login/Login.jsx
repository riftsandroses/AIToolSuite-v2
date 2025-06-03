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
  width: 100%;
  max-width: 420px;
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
`;


const Login = () => {
    const dispatch = useDispatch();
    const [userCreds, setUserCreds] = useState({
        email: "",
        password: "",
    });
    const [errorMsg, setErrorMsg] = useState("");
    const [isLoading, setIsLoading] = useState(false);

    const [openSnackbar, setOpenSnackbar] = useState(false);
    const [snackbarDetails, setSnackbarDetails] = useState({
        type: "",
        message: ""
    });

    const handleSubmit = async (e) => {
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
            const userLoginData = await signInUser({
                email: userCreds.email,
                password: userCreds.password,
            });

            setAuthCookies({
                name: userLoginData.name || "",
                username: userLoginData.username || "",
                email: userLoginData.email || "",
                refreshToken: userLoginData.refresh,
                accessToken: userLoginData.access,
                expiry: 0,
            });

            dispatch(
                loggedInUserSlice.actions.setLogedInUserData({
                    name: userLoginData.name || "",
                    username: userLoginData.username || "",
                    email: userLoginData.email || "",
                    refreshToken: userLoginData.refresh,
                    accessToken: userLoginData.access,
                })
            );

            // Show success message before redirecting
            setSnackbarDetails({
                type: "success",
                message: "Login successful!"
            });
            setOpenSnackbar(true);
            
            window.location.href = "/";
        } catch (error) {
            setErrorMsg(error.response?.data?.error || "Login failed. Please try again.");
        } finally {
            setIsLoading(false);
        }
    };

    const handleChange = (keyName, keyValue) => {
        setUserCreds({
            ...userCreds,
            [keyName]: keyValue
        });
        // Clear error when user types
        if (errorMsg) setErrorMsg("");
    };

    return (
        <LoginContainer>
           <Snackbar 
                openSnackbar={openSnackbar} 
                setOpenSnackbar={setOpenSnackbar} 
                type={snackbarDetails.type} 
                message={snackbarDetails.message} 
            />
            
            <LoginCard>
                <FormTitle>Sign in</FormTitle>
                
                <Form onSubmit={handleSubmit}>
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
                        onClick={handleSubmit}
                        disabled={isLoading}
                    >
                        {isLoading ? "Signing in..." : "Sign in"}
                    </LoginButton>
                </Form>
            </LoginCard>
        </LoginContainer>
    );
};

export default Login;