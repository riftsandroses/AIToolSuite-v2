import { Bolt } from "lucide-react";
import { Database } from "lucide-react";
import { PanelsTopLeft } from "lucide-react";
import { PanelTop } from "lucide-react";


export const menu = [
  //Home
  {
    tabName: "Home",
    path:"/test"
  },

  //⁠Reports & Insights Lab
  {
    tabName: "⁠Reports & Insights Lab",
    subMenu: [
      // {
      //   heading: "ML Model Report ",
      //   options: [
      //     {
      //       name: "Performance Attacks",
      //       desc: "Report",
      //       icon: PanelsTopLeft,
      //       path:""
      //     },
      //     {
      //       name: "Reverse Engineering",
      //       desc: "Report",
      //       icon: Bolt,
      //       path:""

      //     },
      //     {
      //       name: "Explainability Attacks",
      //       desc: "Report",
      //       icon: Bolt,
      //       path:"/"

      //     }
      //   ]
      // },

      {
        heading: "LLM Attack Report",
        options: [
          // {
          //   name: "Prompt Attack ",
          //   desc: "Automation Report",
          //   icon: PanelTop,
          //   path:""

          // },
          // {
          //   name: "Adversarial Attack ",
          //   desc: "Testing Report",
          //   icon: Database,
          //   path:""

          // },
          {
            name: "LLM Vulnerability ",
            desc: "Scanner Report",
            icon: Database,
            path:"/llm-vulnerability-scanner-report"

          },
        ]
      },
      // {
      //   heading: "API Attack Report",
      //   options: [
      //     {
      //       name: "REST Attack ",
      //       desc: "Automation Report",
      //       icon: PanelTop,
      //       path:""

      //     },
      //     {
      //       name: "REST Attack ",
      //       desc: "Automation Report",
      //       icon: Database,
      //       path:""

      //     }
      //   ]
      // },

    ],
  },

  //AI Attack Lab
  {
    tabName: "AI Attack Lab",
    subMenu: [
      // {
      //   heading: "ML Model Suite",
      //   options: [
      //     {
      //       name: "Performance Attacks",
      //       // desc: "Respoesignnsive d",
      //       icon: PanelsTopLeft,
      //       path:""

      //     },
      //     {
      //       name: "Reverse Engineering",
      //       // desc: "Site control",
      //       icon: Bolt,
      //       path:""

      //     },
      //     {
      //       name: "Explainability Attacks",
      //       // desc: "Site control",
      //       icon: Bolt,
      //       path:""

      //     }
      //   ]
      // },

      {
        heading: "LLM Attack Suite",
        options: [
          // {
          //   name: "Prompt Attack Automation",
          //   // desc: "Link pages",
          //   icon: PanelTop,
          //   path:""

          // },
          // {
          //   name: "Adversarial Attack Testing",
          //   // desc: "Management content",
          //   icon: Database,
          //   path:""

          // },
          {
            name: "LLM Vulnerability Scanner",
            // desc: "Management content",
            icon: Database,
            path:"/llm-vulnerability-scanner"

          },
        ]
      },
      {
        heading: "API Attack Suite",
        options: [
          {
            name: "REST Attack Automation",
            // desc: "Link pages",
            icon: PanelTop,
            path:""

          },
          {
            name: "REST Attack Automation",
            // desc: "Management content",
            icon: Database,
            path:""

          }
        ]
      },

    ],
  },

  //Threat Modelling Lab
  // {
  //   tabName: "Threat Modelling Lab",
  //   subMenu: [
  //     {
  //       // heading: "Design",
  //       options: [
  //         {
  //           name: "AI-enabled Threat Modelling",
  //           desc: "Attack",
  //           icon: PanelsTopLeft,
  //           path:""

  //         },

  //       ]
  //     },


  //   ],
  // },


  //Risk Assessment Lab
  {
    tabName: "Risk Assessment Lab",
    path:""

  },
];