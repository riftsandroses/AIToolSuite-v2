import "./App.css";
import { Routes, Route, BrowserRouter } from "react-router";
import { SlideTabsExample } from "./Components/Navbar1/Navbar"
import Navbar2 from "./Components/Navbar2/Navbar";
// import { UserAuth } from "./Guards/UserAuth";


function App() {
  return (
    <div className="bg-[#1f2836] h-[100vh]">
      {/* <SlideTabsExample /> */}
      <Navbar2 />

    </div>

    // <BrowserRouter>
    //   <Routes>
    //     <Route path="/" element={<>Home</>}/>

    //     <Route path="/login" element={<>Login</>} />



    //     <Route
    //       path="/findings"
    //       element={
    //         <UserAuth>
    //           <MainLayout whiteBg={true}>
    //             <Findings />
    //           </MainLayout>
    //         </UserAuth>
    //       }
    //     />
    //   </Routes>
    // </BrowserRouter>
  );
}

export default App;

