import express from "express"
import { countByCity, countByType, createHotel } from "../controllers/hotelController.js";
import { updateHotel } from "../controllers/hotelController.js";
import { deleteHotel } from "../controllers/hotelController.js";
import { getHotel } from "../controllers/hotelController.js";
import { getHotels } from "../controllers/hotelController.js";
import { verifyAdmin } from "../utils/verifyToken.js";
// CRUD routes for hotels.

const router = express.Router();

//CREATE
router.post("/", verifyAdmin, createHotel);

//UPDATE
router.put("/:id", verifyAdmin, updateHotel);

//DELETE
router.delete("/:id", verifyAdmin, deleteHotel);

//GET
router.get("/find/:id", getHotel);

//GET ALL
router.get("/", getHotels);
router.get("/countByCity", countByCity);
router.get("/countByType", countByType);

export default router