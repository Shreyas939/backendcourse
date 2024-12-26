import { Router } from "express";
import {loginUser ,registerUser,logOutUser,refreshAccessToken} from '../controllers/user.controller.js'
import {upload} from "../middlewares/multer.middleware.js"
import {verifyJWT} from "../middlewares/auth.middleware.js"

// same as express app 
const router = Router()

router.route("/register").post(
    upload.fields([  // this is our middleware
        {
            name:"avatar",
            maxCount:1
        },
        {
            name:"coverImage",
            maxCount:1
        }
    ]),
    registerUser
)

router.route("/login").post(loginUser)


//secured routes
router.route("/logout").post(verifyJWT, logOutUser) // that's why we write next() so that run next method after first one
router.route("/refresh-token").post(refreshAccessToken)


export default router