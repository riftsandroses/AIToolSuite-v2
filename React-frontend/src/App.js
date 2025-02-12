import "./App.css";
import { Routes, Route, BrowserRouter } from "react-router";
// import { UserAuth } from "./Guards/UserAuth";


function App() {
  return (

    <BrowserRouter>
      <Routes>
        <Route path="/" element={<>Home</>}/>

        <Route path="/login" element={<>Login</>} />


        
        {/* <Route
          path="/findings"
          element={
            <UserAuth>
              <MainLayout whiteBg={true}>
                <Findings />
              </MainLayout>
            </UserAuth>
          }
        /> */}
      </Routes>
    </BrowserRouter>
  );
}

export default App;

