import "./App.css";
import { Routes, Route, BrowserRouter } from "react-router";
import Header from "./Components/Header/Header";
import Login from "./Pages/Login/Login";
import OpenAI from "./Pages/LLM/OpenAI/OpenAI";
import MainLayout from "./Layout/MainLayout";
// import { UserAuth } from "./Guards/UserAuth";


function App() {
  return (<>


    <BrowserRouter>
      <Routes>
        <Route path="/" element={<>
          <div className="bg-[#1f2836] h-auto">
            <Header />
          </div>
        </>} />

        <Route path="/login" element={<Login />} />
        <Route path="/test" element={
          <MainLayout>
            <OpenAI />
          </MainLayout>
        } />




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
  </>
  );
}

export default App;

