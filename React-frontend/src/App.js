import "./App.css";
import { Routes, Route, BrowserRouter } from "react-router";
import Header from "./Components/Header/Header";
import Login from "./Pages/Login/Login";
import LLMVulnerabilityScanner from "./Pages/LLMVulnerabilityScanner/LLMVulnerabilityScanner";
import MainLayout from "./Layout/MainLayout";
// import { UserAuth } from "./Guards/UserAuth";


function App() {
  return (<>


    <BrowserRouter>
      <Routes className="">
        <Route path="/" element={<>
          <div className="bg-[#1f2836] h-auto">
            <Header />
          </div>
        </>} />

        <Route path="/login" element={<Login />} />
        <Route path="/llm-vulnerability-scanner" element={
          <MainLayout>
            <LLMVulnerabilityScanner />
          </MainLayout>
        } />

        <Route path="/test" element={
          <MainLayout>
            <LLMVulnerabilityScanner />
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

