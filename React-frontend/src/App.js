import "./App.css";
import { Routes, Route, BrowserRouter } from "react-router";
import Header from "./Components/Header/Header";
import Login from "./Pages/Login/Login";
import LLMVulnerabilityScanner from "./Pages/LLMVulnerabilityScanner/LLMVulnerabilityScanner";
import MainLayout from "./Layout/MainLayout";
import { UserAuth } from "./Guards/UserAuth";
import LLMVulnerabilityScannerReport from "./Pages/Reports/LLMVulnerabilityScanner/LLMVulnerabilityScannerReport";
import ScanInsights from "./Pages/Reports/LLMVulnerabilityScanner/ScanInsights";


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
          <UserAuth>
            <MainLayout>
              <LLMVulnerabilityScanner />
            </MainLayout>
          </UserAuth>

        } />

        <Route path="/llm-vulnerability-scanner-report" element={
          // <UserAuth>
            <MainLayout>
              <LLMVulnerabilityScannerReport/>
            </MainLayout>
          // </UserAuth>

        } />

        <Route path="/llm-vulnerability-scanner-report/scan-insights/:id" element={
          // <UserAuth>
            <MainLayout>
              {/* <LLMVulnerabilityScannerReport/> */}
              <ScanInsights/>
            </MainLayout>
          // </UserAuth>

        } />

        <Route path="*" element={
          // <UserAuth>
            <MainLayout>
              Page not found
              <ScanInsights/>
            </MainLayout>
          // </UserAuth>

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

