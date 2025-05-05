        require("dotenv").config();
        const express = require("express");
        const mongoose = require("mongoose");
        const cors = require("cors");
       // const multer = require("multer");
      //  const path = require("path");
        //const jwt = require("jsonwebtoken");
        //const bcrypt = require("bcrypt");
        const app = express();
        const PORT = process.env.PORT || 5050;

        // Middleware
        app.use(express.json());
        app.use(cors());
        app.use("/uploads", express.static("uploads"));

        // Connexion à MongoDB Atlas
        mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        })
        .then(() => console.log("✅ MongoDB Atlas Connected"))
        .catch(err => console.error("❌ MongoDB Connection Error:", err));

        // Schéma des offres d'emploi
        const offreSchema = new mongoose.Schema({
            titre: String,
            description: String,
            entreprise: { type: String, required: true },
            lieu: String, 
            salaire: Number,
            date_publication: Date,
            id_recruteur: String, 
            candidatures: [{ type: mongoose.Schema.Types.ObjectId, ref: "Candidature" }]
        });
        const Offre = mongoose.model("Offre", offreSchema, "offres");

        // Schéma des candidatures
        const candidatureSchema = new mongoose.Schema({
            id_offre: { type: mongoose.Schema.Types.ObjectId, ref: "Offre", required: true },
            id_candidat: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
            cv: String,
            lettre_motivation: String,
            statut: { type: String, default: "en cours" },
            date_postulation: { type: Date, default: Date.now }
        });
        
        const Candidature = mongoose.model("Candidature", candidatureSchema, "candidatures");
        

        const userSchema = new mongoose.Schema({
            nom: String,
            prenom: String,
            email: { type: String, unique: true, required: true },
            mot_de_passe: { type: String, required: true },
            role: { type: String, default: "candidat" }
        });
        
        const User = mongoose.model("User", userSchema, "users");
        app.get("/", (req, res) => {
            res.send("Welcome to the API! Use /products to get data.");
        });

        // Démarrer le serveur
        app.listen(PORT, () => {   
            console.log(`🚀 Serveur en cours d'exécution sur http://localhost:${PORT}`);
        });
            
        module.exports = app;
