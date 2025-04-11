import React from "react";
import { Link } from "react-router-dom";
import logo from "../assets/logos1.svg";

const Navbar = () => {
  return (
    <nav className="w-full bg-[#101B16] text-white px-6 py-4 flex justify-between items-center shadow-md">
      <div className="flex items-center space-x-3">
        <img src={logo} alt="PDFreak Logo" className="w-6 h-6 sm:w-7 sm:h-7" />
        <span className="font-bold text-lg sm:text-xl">PDFreak AI</span>
      </div>
      <div>
        <Link to="/" className="hover:text-green-400 transition">
          Upload
        </Link>
      </div>
    </nav>
  );
};

export default Navbar;
