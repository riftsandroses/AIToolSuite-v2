import React, { forwardRef } from 'react';
import { Input as BaseInput } from '@mui/base/Input';
import { styled } from '@mui/system';

const Input = forwardRef(function CustomInput(props, ref) {
  return <BaseInput slots={{ input: InputElement }} {...props} ref={ref} />;
});

export default function UnstyledInput({ label, placeholder, type = "text", value, handleChange }) {

  return (
    <Input
      id={label}
      aria-label={label}
      placeholder={placeholder}
      type={type}
      value={value}
      onChange={(e) => handleChange(label, e.target.value)}
    />
  )
}

const blue = {
  100: '#DAECFF',
  200: '#b6daff',
  400: '#3399FF',
  500: '#007FFF',
  600: '#0072E5',
  900: '#003A75',
};

const grey = {
  50: '#F3F6F9',
  100: '#E5EAF2',
  200: '#DAE2ED',
  300: '#C7D0DD',
  400: '#B0B8C4',
  500: '#9DA8B7',
  600: '#6B7A90',
  700: '#434D5B',
  800: '#303740',
  900: '#1C2025',
};

const InputElement = styled('input')(
  ({ theme }) => `
  width: 100%;
  font-family: 'IBM Plex Sans', sans-serif;
  font-size: 0.875rem;
  font-weight: 400;
  line-height: 1.5;
  padding: 8px 12px;
  border-radius: 8px;
  color: white;
  // background: ${theme.palette.mode === 'dark' ? grey[900] : 'transparent'};
  background:transparent;
  // border: 1px solid ${theme.palette.mode === 'dark' ? grey[700] : grey[200]};
    border: 2px solid #ffffff1a;

  box-shadow: 0 2px 4px ${theme.palette.mode === 'dark' ? 'rgba(0,0,0, 0.5)' : 'rgba(0,0,0, 0.05)'
    };

  &:hover {
    // border-color: ${blue[400]};
      border-color: #ffffff54;

  }

  &:focus {
    // border-color: ${blue[400]};
      border-color: #805AF5;

    // box-shadow: 0 0 0 3px ${theme.palette.mode === 'dark' ? blue[600] : blue[200]};
  }

  /* firefox */
  &:focus-visible {
    outline: 0;
  }
`,
);
