import React, { forwardRef } from 'react';
import { styled } from '@mui/system';

// Custom Input component to replace the deprecated MUI Base Input
const Input = forwardRef(function CustomInput(
  { label, placeholder, type = "text", value, handleChange, disabled = false, ...props }, 
  ref
) {
  return (
    <InputElement
      id={label}
      aria-label={label}
      placeholder={placeholder}
      type={type}
      value={value}
      onChange={(e) => handleChange && handleChange(label, e.target.value)}
      disabled={disabled}
      ref={ref}
      {...props}
    />
  );
});

export default Input;

const InputElement = styled('input')(
  ({ theme }) => `
  width: 100%;
  font-family: 'IBM Plex Sans', sans-serif;
  font-size: 0.875rem;
  font-weight: 400;
  line-height: 1.5;
  padding: 8px 12px;
  border-radius: 8px;
  margin-bottom: 16px;
  color: white;
  background: transparent;
  border: 2px solid #ffffff1a;
  box-shadow: 0 2px 4px ${theme.palette.mode === 'dark' ? 'rgba(0,0,0, 0.5)' : 'rgba(0,0,0, 0.05)'};

  &:hover {
    border-color: #ffffff54;
  }

  &:focus {
    border-color: #2a3aad;
  }

  &:focus-visible {
    outline: 0;
  }

  &:disabled {
    cursor: not-allowed;
    opacity: 0.7;
    background-color: rgba(255, 255, 255, 0.05);
  }
`);