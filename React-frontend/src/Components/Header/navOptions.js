import { Bolt } from "lucide-react";
// import { ShoppingBag } from "lucide-react";
// import { BellDot } from "lucide-react";
// import { BookOpenText } from "lucide-react";
// import { BriefcaseBusiness } from "lucide-react";
// import { CircleHelp } from "lucide-react";
// import { TriangleAlert } from "lucide-react";
// import { Users } from "lucide-react";
// import { Lock } from "lucide-react";
// import { Dessert } from "lucide-react";
// import { ShieldPlus } from "lucide-react";
// import { MessageCircle } from "lucide-react";
// import { Images } from "lucide-react";
// import { Figma } from "lucide-react";
// import { Play } from "lucide-react";
// import { MapPin } from "lucide-react";
import { Database } from "lucide-react";
import { PanelsTopLeft } from "lucide-react";
import { PanelTop } from "lucide-react";


export const menu = [
  {
    tabName: "Home",
  },
  {
    tabName: "LLM",
    subMenu: [
      {
        heading: "Design",
        options: [
          {
            name: "Design",
            desc: "Responsive design",
            icon: PanelsTopLeft,
          },
          {
            name: "Management",
            desc: "Site control",
            icon: Bolt,
          }
        ]
      },

      {
        heading: "Scale",
        options: [
          {
            name: "Navigation",
            desc: "Link pages",
            icon: PanelTop,
          },
          {
            name: "CMS",
            desc: "Management content",
            icon: Database,
          },
        ]
      },

    ],
  },


  {
    tabName: "Home",
    subMenu: [
      {
        heading: "Design",
        options: [
          {
            name: "Design",
            desc: "Responsive design",
            icon: PanelsTopLeft,
          },
          {
            name: "Management",
            desc: "Site control",
            icon: Bolt,
          },
          {
            name: "Navigation",
            desc: "Link pages",
            icon: PanelTop,
          },
        ]
      },

      {
        heading: "Scale",
        options: [
          {
            name: "Navigation",
            desc: "Link pages",
            icon: PanelTop,
          },
          {
            name: "CMS",
            desc: "Management content",
            icon: Database,
          },
          {
            name: "Navigation",
            desc: "Link pages",
            icon: PanelTop,
          },
          {
            name: "Navigation",
            desc: "Link pages",
            icon: PanelTop,
          },
        ]
      },
      {
        heading: "Scale",
        options: [
          {
            name: "Navigation",
            desc: "Link pages",
            icon: PanelTop,
          },
          {
            name: "Navigation",
            desc: "Link pages",
            icon: PanelTop,
          },
        ]
      },

    ],
  },
  {
    tabName: "Reports",
  },
];