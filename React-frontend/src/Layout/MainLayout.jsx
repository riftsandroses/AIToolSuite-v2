import React from 'react'
import Header from '../Components/Header/Header'

const MainLayout = ({ children }) => {
  return (
    <div className='bg-[#0c0e15] min-h-[100vh]'>
      <Header />
      {children}
    </div>
  )
}

export default MainLayout