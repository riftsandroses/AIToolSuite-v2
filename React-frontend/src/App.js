import "./App.css";
import { Routes, Route, BrowserRouter } from "react-router";
import Header from "./Components/Header/Header";
import Login from "./Pages/Login/Login";
// import { UserAuth } from "./Guards/UserAuth";


function App() {
  return (<>


    <BrowserRouter>
      <Routes>
        <Route path="/" element={<>
          <div className="bg-[#1f2836] h-[120vh]">
            <Header />
          </div>
        </>} />

        <Route path="/login" element={<Login />} />



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

