import {asyncHandler} from '../utils/asyncHandler.js';
import {ApiError} from '../utils/ApiError.js'
import { User} from '../models/user.model.js'
import {uploadOnCloudinary} from '../utils/cloudinary.js'
import {ApiResponse} from '../utils/ApiResponse.js'
import jwt from 'jsonwebtoken'
import { application } from 'express';



const generateAccessAndRefreshTokens = async(userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})

        return {accessToken,refreshToken}


    } catch (error) {
        throw new ApiError(500,"Something went wrong while generating refresh and access token")
    }
}


const registerUser = asyncHandler(async (req,res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username,email
    // check for images,check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    const { fullName,email,username,password } = req.body
    console.log('email: ',email);

    // if(fullName === "" ){
    //     throw new ApiError(400,"fullname required")
    // }

    // better and shorter code 
    if (
        [fullName,email,username,password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400,"all fields required")
    }

    const existedUser = await User.findOne({
        $or: [{username}, {email}]
    })
    if(existedUser){
        throw new ApiError(409,"User with email or username already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath; // with this coverimage can be send empty
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }
    

    if (!avatarLocalPath) {
        throw new ApiError(400,"Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar) {
        throw new ApiError(400,"Avatar file is required")
    }
    

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",  // since we checked for avatar(if there or not) and not for coverImage hence we use optional(?) i.e if present then url or else empty
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering user")
    }

    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registered successfully")
    )

})
  

const loginUser = asyncHandler(async (req,res) => {
    // req body -> data
    // username or email
    // find the user
    // password check
    // access and refresh token
    // send cookies
    // successfull login response

    const {email,username,password} = req.body

    if (!username && !email) {
        throw new ApiError(400,"username or email is required")
    }

    const user = await User.findOne({
        $or: [{username},{email}]       // or is used to find either of them (username or email)
    })

    if (!user) {
        throw new ApiError(404,"User does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if (!isPasswordValid) {
        throw new ApiError(401,"Password is incorrect")
    }


    const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {   // by default cookies are modifiable by anyone in frontend    
        httpOnly:true,  // by writing this now they are modifiable only by server and not by frontend
        secure:true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            200,
            {
                user:loggedInUser,accessToken,refreshToken
            },
            "User logged in Successfully"
        )
    )

})

const logOutUser = asyncHandler(async(req,res) => {
    // clear cookies
    // refresh accessToken
    await User.findByIdAndUpdate(
        req.user._id,
        { // this iis written to specify what is to be updated
            $set:{
                refreshToken:undefined
            }
        },
        {
            new: true
        }
    )
    const options = {
        httpOnly:true,
        secure:true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200,{},"User logged Out"))


})

// making a refresh Access Token endpoint but below is only the controller
const refreshAccessToken = asyncHandler(async(req,res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401,"Unauthorised request")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken,process.env.REFRESH_TOKEN_SECRET)
    
        const user = await User.findById(decodedToken?._id)
    
        if(!user){
            throw new ApiError(401,"Invalid refresh token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401,"Refresh token is expired or used")
        }
    
        const options = {
            httpOnly:true,
            secure:true
        }
    
        const {accessToken,newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
    
        return res
        .status(200,"")
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",newRefreshToken,options)
        .json(
            new ApiResponse(
                200,
                {accessToken,refreshToken:newRefreshToken},
                "Access Token refreshed"
            )
        )
    
    } catch (error) {
        throw new ApiError(401,error?.message || "Invalid refresh token")
    }

})


const changeCurrentPassword = asyncHandler(async(req,res) => {

    const {oldPassword,newPassword} = req.body

    const user = await User.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(400,"Invalid old password")
    }

    user.password = newPassword

    await user.save({validateBeforeSave: false}) // while saving user i dont want other validations to run hence false

    return res
    .status(200)
    .json(new ApiResponse(200,{/*no data */} ,"Password changed successfully"))




})

const  getCurrentUser = asyncHandler(async(req,res) => {
    return res
    .status(200)
    .json(new ApiResponse(200,req.user,"Current user fetched successfully"))
})

const updateAccountDetails = asyncHandler(async(req,res) => {
    const {fullName,email} = req.body           // depends on us what to allow user to update

    if(!fullName || !email){
        throw new ApiError(400,"All fields are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,         // Find the user document by ID
        {
            $set: {            // Update the specified fields
                fullName,      // Update 'fullName' with the provided value
                email          // Update 'email' with the provided value
            }
        },
        { new: true }          // Return the updated document after modification
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200,user,"Account details updated successfully"))
    


})


const updateUserAvatar = asyncHandler(async(req,res) => {
    const avatarLocalPath = req.file?.path // got this thorugh multer middleware

    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400,"Error while uploading on avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar:avatar.url
            }
        },
        {new:true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200,{user},"Avatar updated Successfully"))


})

const updateUserCoverImage = asyncHandler(async(req,res) => {
    const coverImageLocalPath = req.file?.path // got this thorugh multer middleware

    if(!coverImageLocalPath){
        throw new ApiError(400,"coverImage file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400,"Error while uploading on coverImage")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage:coverImage.url
            }
        },
        {new:true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200,{user},"coverImage updated Successfully"))


})


const getUserChannelProfile = asyncHandler(async(req,res) => {

    const {username} = req.params

    if(!username?.trim()) {
        throw new ApiError(400,"Username does not exist")
    }

    const channel = await User.aggregate([
        // Stage 1: Match the user by username (case insensitive)
        {
            $match: {
                username: username?.toLowerCase() // Match the provided username after converting to lowercase
            }
        },
    
        // Stage 2: Lookup subscribers for the user
        {
            $lookup: {
                from: "subscriptions",              // Join with the 'subscriptions' collection
                localField: "_id",                  // Match '_id' of the user
                foreignField: "channel",            // Match 'channel' field in subscriptions
                as: "subscribers"                   // Output the results into 'subscribers' array
            }
        },
    
        // Stage 3: Lookup channels the user is subscribed to
        {
            $lookup: {
                from: "subscriptions",              // Join with the 'subscriptions' collection
                localField: "_id",                  // Match '_id' of the user
                foreignField: "subscriber",         // Match 'subscriber' field in subscriptions
                as: "subscribedTo"                  // Output the results into 'subscribedTo' array
            }
        },
    
        // Stage 4: Add computed fields to the output
        {
            $addFields: {
                subscribersCount: {
                    $size: "$subscribers"           // Count the number of subscribers
                },
                channelsSubcribedToCount: {
                    $size: "$subscribedTo"          // Count the number of channels the user is subscribed to
                },
                isSubscribed: {
                    $cond: {                         // Conditional check if the current user is subscribed
                        if: { $in: [req.user?._id, "$subscribers.subscriber"] }, // Check if current user ID exists in subscribers
                        then: true,                  // If exists, set to true
                        else: false                  // Otherwise, set to false
                    }
                }
            }
        },
    
        // Stage 5: Project only required fields to the output
        {
            $project: {
                fullName: 1,                         // Include fullName field
                username: 1,                         // Include username field
                subscribersCount: 1,                 // Include subscribers count
                channelsSubcribedToCount: 1,         // Include subscribed-to count
                isSubscribed: 1,                      // Include subscription status
                avatar: 1,                           // Include avatar field
                coverImage: 1,                       // Include cover image field
                email: 1                             // Include email field
            }
        }
    ]);
    

    if(!channel?.length){
        throw new ApiError(404,"Channel does not exist")
    }

    return res
    .status(200)
    .json(new ApiResponse(200,channel[0],"User channel fetched successfully"))

})


export {registerUser,getUserChannelProfile,loginUser,updateUserCoverImage,logOutUser,refreshAccessToken,changeCurrentPassword,getCurrentUser,updateAccountDetails,updateUserAvatar}