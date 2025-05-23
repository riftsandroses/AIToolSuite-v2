import { useState, useRef, useEffect } from 'react';
import { Transition } from 'react-transition-group';
import { styled } from '@mui/system';
import ErrorOutlineOutlinedIcon from '@mui/icons-material/ErrorOutlineOutlined';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CloseIcon from '@mui/icons-material/Close';

// Custom Snackbar component to replace the deprecated MUI Base Snackbar
export default function Snackbar({ openSnackbar, setOpenSnackbar, type, message }) {
  const [exited, setExited] = useState(true);
  const nodeRef = useRef(null);
  
  // Auto-hide functionality
  useEffect(() => {
    let timer;
    if (openSnackbar) {
      timer = setTimeout(() => {
        setOpenSnackbar(false);
      }, 4000);
    }
    
    return () => {
      clearTimeout(timer);
    };
  }, [openSnackbar, setOpenSnackbar]);

  const handleClose = (_, reason) => {
    if (reason === 'clickaway') {
      return;
    }
    setOpenSnackbar(false);
  };

  const handleOnEnter = () => {
    setExited(false);
  };

  const handleOnExited = () => {
    setExited(true);
  };

  // Only render if open or exiting
  if (!openSnackbar && exited) return null;
  
  return (
    <StyledSnackbarContainer>
      <Transition
        timeout={{ enter: 400, exit: 400 }}
        in={openSnackbar}
        appear
        unmountOnExit
        onEnter={handleOnEnter}
        onExited={handleOnExited}
        nodeRef={nodeRef}
      >
        {(status) => (
          <SnackbarContent
            style={{
              transform: positioningStyles[status],
              transition: 'transform 300ms ease',
              background: type === "success" ? "#43a047" : "rgb(22, 11, 11)",
              color: type === "success" ? "white" : "rgb(244, 199, 199)"
            }}
            ref={nodeRef}
          >
            {type === "success" && 
              <CheckCircleIcon
                sx={{
                  color: 'white',
                  flexShrink: 0,
                  width: '1.25rem',
                  height: '1.5rem',
                }}
              />
            }
            {type === "error" && 
              <ErrorOutlineOutlinedIcon
                sx={{
                  color: 'red',
                  flexShrink: 0,
                  width: '1.25rem',
                  height: '1.5rem',
                }}
              />
            }

            <div className="snackbar-message">
              <p className="snackbar-title">{message}</p>
            </div>
            <CloseIcon 
              onClick={() => handleClose(null, 'close')} 
              className="snackbar-close-icon" 
              sx={{
                cursor: 'pointer',
                flexShrink: 0,
                padding: '2px',
                borderRadius: '20px',
                '&:hover': {
                  background: 'rgba(255, 255, 255, 0.08)'
                }
              }}
            />
          </SnackbarContent>
        )}
      </Transition>
    </StyledSnackbarContainer>
  );
}

const StyledSnackbarContainer = styled('div')`
  position: fixed;
  z-index: 5500;
  display: flex;
  top: 16px;
  right: 1rem;
  max-width: 560px;
`;

const SnackbarContent = styled('div')(
  ({ theme }) => `
    display: flex;
    gap: 8px;
    overflow: hidden;
    border-radius: 8px;
    box-shadow: 0 2px 16px rgb(0 0 0 / 0.5);
    padding: 0.75rem;
    font-family: 'IBM Plex Sans', sans-serif;
    font-weight: 500;
    text-align: start;
    position: relative;

    & .snackbar-message {
      flex: 1 1 0%;
      max-width: 100%;
    }

    & .snackbar-title {
      margin: 0;
      line-height: 1.5rem;
      margin-right: 0.5rem;
    }

    & .snackbar-close-icon {
      cursor: pointer;
      flex-shrink: 0;
      padding: 2px;
      border-radius: 20px;

      &:hover {
        background: rgba(255, 255, 255, 0.08);
      }
    }
  `
);

const positioningStyles = {
  entering: 'translateX(0)',
  entered: 'translateX(0)',
  exiting: 'translateX(500px)',
  exited: 'translateX(500px)',
  unmounted: 'translateX(500px)',
};