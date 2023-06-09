import Room from "../models/Room.js"
import Hotel from "../models/Hotel.js"

import { createError } from "../utils/error.js"

export const createRoom = async (req, res, next) => {

    const hotelId = req.params.hotelid;
    const newRoom = new Room(req.body)

try {
    const savedRoom = await newRoom.save()
    try {
       await Hotel.findByIdAndUpdate(hotelId, {$push: { rooms: savedRoom._id},
    });
    } catch (err) {
    next(err) 
    }
    res.status(200).json(savedRoom);
} catch (err) {
    next(err)
}

};

// Update room controller function. 
export const updateRoom = async (req,res,next) => {
    // Update room information based on user entry.
    try{
        /* Find room by id 
        and update db with the information entered by the user.
        Return the updated doc. */
        const updatedRoom = await Room.findByIdAndUpdate(
            req.params.id,
            { $set: req.body },
            { new: true }
        );
        res.status(200).json(updatedRoom)
    }catch(err){
        next(err);
    }
};

// Delete room controller function. 
export const deleteRoom = async (req, res, next) => {
    const hotelId = req.params.hotelid;
    try {
      await Room.findByIdAndDelete(req.params.id);
      try {
        await Hotel.findByIdAndUpdate(hotelId, {
          $pull: { rooms: req.params.id },
        });
      } catch (err) {
        next(err);
      }
      res.status(200).json("Room has been deleted.");
    } catch (err) {
      next(err);
    }
  };

// Get a room controller function. 
export const getRoom = async (req,res,next) => {
    
    try{
        // Find room by id return doc from db.
        const room = await Room.findById(
            req.params.id
        );
        res.status(200).json(room)
    }catch(err){
        next(err);
    }
};

// Get all rooms controller function. 
export const getRooms = async (req,res,next) => {
    
    try{
        // Get all room docs from the db and display them.
        const rooms = await Room.find(
        );
        res.status(200).json(rooms)
    }catch(err){
        next(err)
    }
};