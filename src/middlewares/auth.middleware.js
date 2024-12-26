import {ApiError} from "../utils/ApiError.js"
import {asyncHandler} from "../utils/asyncHandler.js"
import jwt from "jsonwebtoken"
import {User} from "../models/user.model.js"
// this is verify if user is there or not there

export const verifyJWT = asyncHandler(async(req,res,next) => {
   
    try {
    const token =  req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ","") // this ,means ya to cookies se token nikal lo ya to req.header authorization se nikal lo 
 
    if(!token){
     throw new ApiError(401,"Unauthorised request")
    }
 
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
 
    const user = await User.findById(decodedToken?._id).select("-password -refreshToken")   
 
    if(!user) {
         throw new ApiError(401,"Invalid Access Token")
    }
    req.user = user;
    next()
   } catch (error) {
        throw new ApiError(401, error?.message || "Invalid Access Token")
   }


})