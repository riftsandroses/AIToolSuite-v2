import React from 'react'
import Header from '../Components/Header/Header'

const MainLayout = ({ children }) => {
  return (
    <div className='bg-[#1f2836]'>
      <Header />
      {children}
    </div>
  )
}

export default MainLayout